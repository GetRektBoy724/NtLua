#include "crt/crt.h"
#include <ntifs.h>
#include <intrin.h>
#include "logger.hpp"
#include "trace_ring.hpp"
#include "log_ring.hpp"
#include "lua/vm.hpp"
#include "lua/state.hpp"
#include "lua/native_function.hpp"
#include "driver_io.hpp"
#include "lua/api.hpp"
#include "lua/callback.hpp"
#include "lua/ioctl.hpp"

#pragma intrinsic(_enable)

// Global Lua context and attaching helpers.
//
IO_REMOVE_LOCK remove_lock = {};

// Bounded wait for a chunk execution (NTLUA_INSTANCE_RUN). A script wedged
// inside a blocking native FFI call can never be preempted (the instruction
// hook only fires between Lua instructions), so the IRP gives up after this
// long; the execution thread keeps running in the background and aborts via
// the instruction budget the moment control returns to Lua.
//
static constexpr LONGLONG NTLUA_RUN_TIMEOUT_MS = 30000;

struct captured_buffer
{
    char*  data   = nullptr;
    size_t length = 0;
};

// One chunk-execution request. Allocated as a single pool block with the code
// and chunk name appended; owned by the execution thread, which frees it after
// the caller has either consumed the results or given up (abort).
//
struct execution_request
{
    vm_instance* instance;            // the VM this chunk executes on
    char* code;                       // points into this allocation
    char* chunkname;                  // points into this allocation
    captured_buffer errors_copy;      // filled by the execution thread
    captured_buffer outputs_copy;
    KEVENT done_event;                // execution thread finished
    KEVENT consumed_event;            // caller exported the buffers
    KEVENT abort_event;               // caller timed out / gave up
};

// Executes one chunk on its own system thread so the caller can bound the
// wait. Runs under the instance's lock exactly like the old inline
// path, then hands the captured output to the caller and only frees the
// request once the caller has consumed it or signalled abort.
//
static VOID NTAPI vm_execution_worker( PVOID start_context )
{
    execution_request* req = ( execution_request* ) start_context;
    vm_instance* inst = req->instance;

    {
        unique_lock _g{ inst->lock };

        // Queued behind a wedged chunk and the caller gave up meanwhile - do
        // no work, just free the request.
        //
        if ( !KeReadStateEvent( &req->abort_event ) )
        {
            vm::begin_ctx( inst );
            logger::route_begin( inst->log_session );

            // Snapshot the write position before running the chunk so the
            // return value contains ONLY this chunk's output. Output produced
            // in between chunks - by a worker poll or a callback firing while
            // the instance lock was free - is dropped from the session here
            // (it already reached the tail log ring via fwrite) instead of
            // leaking into the next REPL return.
            //
            size_t logs_start   = 0;
            size_t errors_start = 0;
            if ( inst->log_session )
            {
                logs_start   = inst->log_session->logs.iterator;
                errors_start = inst->log_session->errors.iterator;
            }

            lua::execute( inst->L, req->code, true, req->chunkname );
            logger::route_end();
            vm::end_ctx( inst );

            // Capture only [start, iterator): the bytes this chunk wrote.
            // Then consume the whole buffer so pre-chunk output (worker /
            // callback prints) can never surface in a later REPL return.
            //
            const auto capture = [ ] ( logger::string_buffer& buf, size_t start ) -> captured_buffer
            {
                captured_buffer out;
                size_t avail = buf.iterator - start;
                if ( avail )
                {
                    out.data = ( char* ) malloc( avail + 1 );
                    if ( out.data )
                    {
                        memcpy( out.data, buf.raw + start, avail );
                        out.length = avail;
                        out.data[ out.length ] = 0;
                    }
                }

                buf.read_pos = buf.iterator;
                if ( buf.read_pos >= buf.buffer_length / 2 )
                {
                    buf.iterator = 0;
                    buf.read_pos = 0;
                }
                return out;
            };

            if ( inst->log_session )
            {
                req->errors_copy  = capture( inst->log_session->errors, errors_start );
                req->outputs_copy = capture( inst->log_session->logs, logs_start );
            }

            // Flush any trailing partial line (print() without a newline) so
            // it still shows up in the tail log ring.
            //
            log_ring::flush_partial();
        }
    }

    // Release the lock before waiting: the user-mode export below must not
    // happen under the VM lock.
    //
    KeSetEvent( &req->done_event, IO_NO_INCREMENT, FALSE );

    PVOID handoff[ 2 ] = { &req->consumed_event, &req->abort_event };
    KeWaitForMultipleObjects( 2, handoff, WaitAny, Executive, KernelMode, FALSE, nullptr, nullptr );

    free( req );
    PsTerminateSystemThread( STATUS_SUCCESS );
}

// Device control handler.
//
NTSTATUS device_control( PDEVICE_OBJECT device_object, PIRP irp )
{
    NTSTATUS remove_status = IoAcquireRemoveLock( &remove_lock, irp );
    if ( !NT_SUCCESS( remove_status ) )
    {
        irp->IoStatus.Status = remove_status;
        irp->IoStatus.Information = 0;
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return remove_status;
    }

    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation( irp );

    // Reset a single VM instance: destroy its Lua state + callbacks and
    // re-create a fresh one (same log session, same instance slot, same
    // instance id). The instance lock is held throughout, so dispatch is
    // blocked; concurrent dispatches that have already resolved `owner` see
    // inst->L == nullptr under the lock and bail to the fallback. Returns
    // STATUS_INSUFFICIENT_RESOURCES on re-init failure (instance is left in
    // a torn-down state — caller can vm kill it and vm new a fresh one).
    //
    auto reset_instance = [ & ] ( vm_instance* inst ) -> NTSTATUS
    {
        unique_lock _g{ inst->lock };
        callback::run_teardown( inst );
        callback::destroy( inst );
        lua::destroy( inst->L );
        inst->L = lua::init();
        if ( !inst->L )
            return STATUS_INSUFFICIENT_RESOURCES;

        lua::set_context_owner( inst->L, inst );
        lua::expose_api( inst->L );
        callback::init();
        callback::expose_api( inst->L );
        ioctl::expose_api( inst->L );
        return STATUS_SUCCESS;
    };

    // Handle the command.
    //
    if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_INSTANCE_RESET )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        if ( !buf || sp->Parameters.DeviceIoControl.InputBufferLength < sizeof( unsigned int ) )
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INVALID_PARAMETER;
        }
        unsigned int id = *( unsigned int* ) buf;
        vm_instance* inst = vm::by_id( id );
        if ( !inst )
        {
            irp->IoStatus.Status = STATUS_NOT_FOUND;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_NOT_FOUND;
        }
        NTSTATUS reset_status = reset_instance( inst );
        if ( !NT_SUCCESS( reset_status ) )
        {
            irp->IoStatus.Status = reset_status;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return reset_status;
        }
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_TAIL_TRACE )
    {
        irp->IoStatus.Information = 0;
        NTSTATUS trace_status = trace::tail_trace( irp, sp );
        if ( !NT_SUCCESS( trace_status ) )
        {
            irp->IoStatus.Status = trace_status;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return trace_status;
        }
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_TRACE_CTL )
    {
        irp->IoStatus.Information = 0;
        NTSTATUS trace_status = trace::trace_ctl( irp, sp );
        if ( !NT_SUCCESS( trace_status ) )
        {
            irp->IoStatus.Status = trace_status;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return trace_status;
        }
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_TAIL_LOG )
    {
        irp->IoStatus.Information = 0;
        NTSTATUS log_status = log_ring::tail_log( irp, sp );
        if ( !NT_SUCCESS( log_status ) )
        {
            irp->IoStatus.Status = log_status;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return log_status;
        }
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_INSTANCE_LIST )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        size_t out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if ( !buf || out_len < sizeof( ntlua_instance_list_out ) )
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INVALID_PARAMETER;
        }
        ntlua_instance_list_out* out = ( ntlua_instance_list_out* ) buf;
        RtlZeroMemory( out, sizeof( *out ) );
        for ( int i = 0; i < vm::MAX_INSTANCES; i++ )
        {
            if ( vm::instances[ i ].active )
            {
                out->ids[ out->count ] = ( unsigned int ) i;
                out->worker_running[ out->count ] = vm::instances[ i ].worker_running ? 1 : 0;
                out->count++;
            }
        }
        irp->IoStatus.Information = sizeof( ntlua_instance_list_out );
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_INSTANCE_CREATE )
    {
        vm_instance* inst = vm::alloc();
        if ( !inst )
        {
            irp->IoStatus.Status = STATUS_TOO_MANY_COMMANDS;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_TOO_MANY_COMMANDS;
        }

        inst->log_session = vm::create_session();
        inst->L = lua::init();
        if ( !inst->L )
        {
            vm::destroy_session( inst->log_session );
            inst->log_session = nullptr;
            vm::free( inst );
            irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        lua::set_context_owner( inst->L, inst );
        lua::expose_api( inst->L );
        callback::expose_api( inst->L );
        ioctl::expose_api( inst->L );
        vm::start_worker( inst );

        unsigned int new_id = inst->id;
        void* buf = irp->AssociatedIrp.SystemBuffer;
        if ( buf && sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof( unsigned int ) )
        {
            *( unsigned int* ) buf = new_id;
            irp->IoStatus.Information = sizeof( unsigned int );
        }
        else
        {
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_BUFFER_TOO_SMALL;
        }
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_INSTANCE_DESTROY )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        if ( !buf || sp->Parameters.DeviceIoControl.InputBufferLength < sizeof( unsigned int ) )
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INVALID_PARAMETER;
        }

        unsigned int id = *( unsigned int* ) buf;
        vm_instance* inst = vm::by_id( id );
        if ( !inst )
        {
            irp->IoStatus.Status = STATUS_NOT_FOUND;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_NOT_FOUND;
        }

        unique_lock _g{ inst->lock };
        callback::run_teardown( inst );
        callback::destroy( inst );
        lua::destroy( inst->L );
        inst->L = nullptr;
        vm::destroy_session( inst->log_session );
        inst->log_session = nullptr;
        vm::free( inst );
        irp->IoStatus.Information = 0;
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_INSTANCE_WORKER_CTL )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        if ( !buf || sp->Parameters.DeviceIoControl.InputBufferLength < sizeof( ntlua_instance_worker_ctl ) )
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INVALID_PARAMETER;
        }
        ntlua_instance_worker_ctl* in = ( ntlua_instance_worker_ctl* ) buf;
        vm_instance* inst = vm::by_id( in->id );
        if ( !inst )
        {
            irp->IoStatus.Status = STATUS_NOT_FOUND;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_NOT_FOUND;
        }
        // Set under the instance lock so a concurrent worker thread reads a
        // consistent value (the thread reads worker_running outside the lock
        // for its off-sleep, but only the off-sleep branch cares; the lock
        // acquire on the next poll iteration provides the memory barrier).
        //
        unique_lock _g{ inst->lock };
        inst->worker_running = ( in->enable != 0 );
        irp->IoStatus.Information = 0;
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_INSTANCE_RUN )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        size_t in_len = sp->Parameters.DeviceIoControl.InputBufferLength;
        if ( !buf || in_len <= sizeof( ntlua_instance_run_in ) )
        {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INVALID_PARAMETER;
        }

        ntlua_instance_run_in* in = ( ntlua_instance_run_in* ) buf;
        vm_instance* inst = vm::by_id( in->id );
        if ( !inst || !inst->L )
        {
            irp->IoStatus.Status = STATUS_NOT_FOUND;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_NOT_FOUND;
        }

        const char* code = in->code;
        const char* chunkname = "instance";
        size_t avail = in_len - sizeof( ntlua_instance_run_in );
        size_t name_len = 0;
        while ( name_len < avail && in->code[ name_len ] != 0 )
            name_len++;
        if ( name_len + 1 < avail )
        {
            chunkname = in->code;
            code = in->code + name_len + 1;
        }

        size_t code_len = strlen( code );
        size_t name_len_out = strlen( chunkname );
        execution_request* req = ( execution_request* ) malloc(
            sizeof( execution_request ) + code_len + 1 + name_len_out + 1 );
        if ( !req )
        {
            irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        req->code = ( char* ) ( req + 1 );
        req->chunkname = req->code + code_len + 1;
        req->instance = inst;
        memcpy( req->code, code, code_len + 1 );
        memcpy( req->chunkname, chunkname, name_len_out + 1 );
        KeInitializeEvent( &req->done_event, NotificationEvent, FALSE );
        KeInitializeEvent( &req->consumed_event, NotificationEvent, FALSE );
        KeInitializeEvent( &req->abort_event, NotificationEvent, FALSE );

        HANDLE thread_handle = nullptr;
        NTSTATUS create_status = PsCreateSystemThread(
            &thread_handle, 0, nullptr, nullptr, nullptr, &vm_execution_worker, req );
        if ( !NT_SUCCESS( create_status ) )
        {
            free( req );
            irp->IoStatus.Status = create_status;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return create_status;
        }
        if ( thread_handle ) ZwClose( thread_handle );

        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000 * NTLUA_RUN_TIMEOUT_MS;
        NTSTATUS wait_status = KeWaitForSingleObject(
            &req->done_event, Executive, KernelMode, FALSE, &timeout );
        if ( wait_status == STATUS_TIMEOUT )
        {
            KeSetEvent( &req->abort_event, IO_NO_INCREMENT, FALSE );
            irp->IoStatus.Status = STATUS_TIMEOUT;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_TIMEOUT;
        }

        const auto export_to_um = [ ] ( captured_buffer& buf ) -> char*
        {
            if ( !buf.data )
                return nullptr;
            char* region = nullptr;
            size_t size = buf.length + 1;
            ZwAllocateVirtualMemory( NtCurrentProcess(), ( void** ) &region, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if ( region )
            {
                __try
                {
                    memcpy( region, buf.data, buf.length );
                    region[ buf.length ] = 0;
                }
                __except ( 1 )
                {
                    region = nullptr;
                }
            }
            // Free the captured source after copying: it is owned by the
            // request and would otherwise leak per execution (non-paged pool).
            //
            free( buf.data );
            buf.data = nullptr;
            return region;
        };

        size_t out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if ( out_len >= sizeof( ntlua_instance_run_out ) )
        {
            ntlua_instance_run_out* out = ( ntlua_instance_run_out* ) buf;
            out->errors  = export_to_um( req->errors_copy );
            out->outputs = export_to_um( req->outputs_copy );
        }
        KeSetEvent( &req->consumed_event, IO_NO_INCREMENT, FALSE );
        irp->IoStatus.Information = sizeof( ntlua_instance_run_out );
    }
    else
    {
        // Script-registered IOCTL handlers (nt.register_ioctl). Every code
        // that is not a built-in NTLUA_* code lands here: if a script has
        // claimed it, the driver runs the handler and completes the IRP with
        // the handler's status/output; otherwise the default is
        // STATUS_INVALID_DEVICE_REQUEST. ioctl::dispatch sets
        // IoStatus.Status/Information but leaves the remove-lock release and
        // IRP completion to us, like every other branch.
        //
        ioctl::dispatch( irp, sp );

        IoReleaseRemoveLock( &remove_lock, irp );
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return irp->IoStatus.Status;
    }

    // Declare success and return.
    //
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoReleaseRemoveLock( &remove_lock, irp );
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

// Unloads the driver.
//
void unload_driver( PDRIVER_OBJECT driver )
{
    IoReleaseRemoveLockAndWait( &remove_lock, nullptr );

    // Deactivate all callbacks (trampolines become no-ops).
    //
    callback::begin_teardown();

    // Destroy all VM instances (each runs its own teardown, then its Lua
    // state and session are freed).
    //
    vm::shutdown();

    // Logger must be freed after all instances (they may still hold the
    // global session on instance 0). See vm::destroy_session.
    //
    logger::shutdown();

    // Delete the symbolic link.
    //
    UNICODE_STRING sym_link;
    RtlInitUnicodeString( &sym_link, L"\\DosDevices\\NtLua" );
    IoDeleteSymbolicLink( &sym_link );

    // Delete the device object.
    //
    if ( PDEVICE_OBJECT device_object = driver->DeviceObject )
        IoDeleteDevice( device_object );
}

// Execute corporate-level security check.
//
NTSTATUS security_check( PDEVICE_OBJECT device_object, PIRP irp )
{
    NTSTATUS remove_status = IoAcquireRemoveLock( &remove_lock, irp );
    if ( !NT_SUCCESS( remove_status ) )
    {
        irp->IoStatus.Status = remove_status;
        irp->IoStatus.Information = 0;
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return remove_status;
    }

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoReleaseRemoveLock( &remove_lock, irp );
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

// Entry-point.
//
extern "C" NTSTATUS DriverEntry( DRIVER_OBJECT* DriverObject, UNICODE_STRING* RegistryPath )
{
    // Logger before anything can print into it (pool-backed, see logger.hpp).
    //
    logger::init();

    // Run static initializers.
    //
    crt::initialize();

    // Trace ring before any VM execution can emit into it.
    //
    trace::init();

    // Tail log ring before any print() can emit into it.
    //
    log_ring::init();

    // Initialize the universal callback bridge (trampoline table, rundown,
    // registry spinlock). Must precede any instance that registers callbacks.
    //
    callback::init();

    // Create the device object.
    //
    UNICODE_STRING device_name;
    RtlInitUnicodeString( &device_name, L"\\Device\\NtLua" );

    PDEVICE_OBJECT device_object;
    NTSTATUS nt_status = IoCreateDevice
    (
        DriverObject,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_object 
    );
    if ( !NT_SUCCESS( nt_status ) )
        return nt_status;

    IoInitializeRemoveLock( &remove_lock, 0x4E744C75, 0, 0 );

    // Set callbacks.
    //
    DriverObject->DriverUnload = &unload_driver;
    DriverObject->MajorFunction[ IRP_MJ_CREATE ] = &security_check;
    DriverObject->MajorFunction[ IRP_MJ_CLOSE ] = &security_check;
    DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = &device_control;
    
    // Create a symbolic link.
    //
    UNICODE_STRING dos_device;
    RtlInitUnicodeString( &dos_device, L"\\DosDevices\\NtLua" );
    nt_status = IoCreateSymbolicLink( &dos_device, &device_name );
    if ( !NT_SUCCESS( nt_status ) )
    {
        IoDeleteDevice( device_object );
        return nt_status;
    }

    // Create the default instance (instance 0): Lua state, API, instance
    // ownership and callback API.
    //
    vm::init();
    if ( !vm::instances[ 0 ].active || !vm::instances[ 0 ].L )
    {
        IoDeleteSymbolicLink( &dos_device );
        IoDeleteDevice( device_object );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}
