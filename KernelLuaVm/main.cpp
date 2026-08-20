#include "crt/crt.h"
#include <ntifs.h>
#include <intrin.h>
#include "logger.hpp"
#include "trace_ring.hpp"
#include "log_ring.hpp"
#include "lua/state.hpp"
#include "lua/native_function.hpp"
#include "driver_io.hpp"
#include "lua/api.hpp"
#include "lua/callback.hpp"

#pragma intrinsic(_enable)

// Global Lua context and attaching helpers.
//
lua_State* L = nullptr;
vm_lock LL = {};
IO_REMOVE_LOCK remove_lock = {};

PEPROCESS attached_process = nullptr;
KAPC_STATE apc_state;
volatile void* context_owner = nullptr;
bool context_active = false;
bool process_attached = false;

namespace lua
{
    static void begin_ctx()
    {
        context_owner = ( void* ) KeGetCurrentThread();
        context_active = true;
        if ( attached_process )
        {
            if ( PsGetProcessExitStatus( attached_process ) != STATUS_PENDING )
            {
                ObDereferenceObject( attached_process );
                attached_process = nullptr;
            }
            else
            {
                KeStackAttachProcess( attached_process, &apc_state );
                process_attached = true;
            }
        }
    }
    static void end_ctx()
    {
        __writecr8( 0 );
        _enable();
        if ( process_attached )
        {
            KeUnstackDetachProcess( &apc_state );
            process_attached = false;
        }
        context_active = false;
        context_owner = nullptr;
    }

    bool detach()
    {
        if ( !context_active || context_owner != ( void* ) KeGetCurrentThread() )
            return false;
        if ( process_attached )
        {
            KeUnstackDetachProcess( &apc_state );
            process_attached = false;
        }
        ObDereferenceObject( attached_process );
        attached_process = nullptr;
        return true;
    }
    bool attach_process( PEPROCESS process )
    {
        if ( !context_active || context_owner != ( void* ) KeGetCurrentThread() )
            return false;
        if ( !ObReferenceObjectSafe( process ) )
            return false;

        detach();
        attached_process = process;
        KeStackAttachProcess( process, &apc_state );
        process_attached = true;
        return true;
    }
    bool attach_pid( uint64_t pid )
    {
        if ( !context_active || context_owner != ( void* ) KeGetCurrentThread() )
            return false;

        PEPROCESS process = nullptr;
        PsLookupProcessByProcessId( ( HANDLE ) pid, &process );
        if ( !process ) 
            return false;

        if ( process_attached )
        {
            KeUnstackDetachProcess( &apc_state );
            process_attached = false;
        }
        if ( attached_process )
            ObDereferenceObject( attached_process );
        attached_process = process;
        KeStackAttachProcess( process, &apc_state );
        process_attached = true;
        return true;
    }
};

// Bounded wait for a NTLUA_RUN chunk. A script wedged inside a blocking
// native FFI call can never be preempted (the instruction hook only fires
// between Lua instructions), so the IRP gives up after this long; the
// execution thread keeps running in the background and aborts via the
// instruction budget the moment control returns to Lua.
//
static constexpr LONGLONG NTLUA_RUN_TIMEOUT_MS = 30000;

struct captured_buffer
{
    char*  data   = nullptr;
    size_t length = 0;
};

// One NTLUA_RUN request. Allocated as a single pool block with the code and
// chunk name appended; owned by the execution thread, which frees it after
// the caller has either consumed the results or given up (abort).
//
struct execution_request
{
    char* code;                       // points into this allocation
    char* chunkname;                  // points into this allocation
    captured_buffer errors_copy;      // filled by the execution thread
    captured_buffer outputs_copy;
    KEVENT done_event;                // execution thread finished
    KEVENT consumed_event;            // caller exported the buffers
    KEVENT abort_event;               // caller timed out / gave up
};

// Executes one chunk on its own system thread so the NTLUA_RUN IOCTL can
// bound the wait. Runs under LL exactly like the old inline path, then hands
// the captured output to the caller and only frees the request once the
// caller has consumed it or signalled abort.
//
static VOID NTAPI vm_execution_worker( PVOID start_context )
{
    execution_request* req = ( execution_request* ) start_context;

    {
        unique_lock _g{ LL };

        // Queued behind a wedged chunk and the caller gave up meanwhile - do
        // no work, just free the request.
        //
        if ( !KeReadStateEvent( &req->abort_event ) )
        {
            lua::begin_ctx();
            lua::execute( L, req->code, true, req->chunkname );
            lua::end_ctx();

            // Capture only the output produced since the last capture
            // (watermark), so print() from callbacks that fire between
            // chunks is preserved instead of wiped by the next chunk.
            //
            const auto capture = [ ] ( logger::string_buffer& buf ) -> captured_buffer
            {
                captured_buffer out;
                size_t avail = buf.iterator - buf.read_pos;
                if ( avail )
                {
                    out.data = ( char* ) malloc( avail + 1 );
                    if ( out.data )
                    {
                        out.length = buf.capture_delta( out.data, avail );
                        out.data[ out.length ] = 0;
                    }
                }
                return out;
            };

            if ( logger::global )
            {
                req->errors_copy  = capture( logger::global->errors );
                req->outputs_copy = capture( logger::global->logs );
            }

            // Flush any trailing partial line (print() without a newline) so
            // it still shows up in the tail log ring.
            //
            log_ring::flush_partial();
        }
    }

    // Release LL before waiting: the user-mode export below must not happen
    // under the VM lock.
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

    // Handle the command.
    //
    if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_RESET )
    {
        callback::begin_teardown();
        unique_lock _g{ LL };
        callback::run_teardown( L );
        callback::destroy( L );
        lua::destroy( L );
        L = lua::init();
        if ( !L )
        {
            callback::init();
            irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // A reset VM is useless without its API (the old code re-created a
        // bare state with no globals exposed).
        //
        lua::expose_api( L );
        callback::init();
        callback::expose_api( L );
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_RUN )
    {
        if ( !L )
        {
            irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
            irp->IoStatus.Information = 0;
            IoReleaseRemoveLock( &remove_lock, irp );
            IoCompleteRequest( irp, IO_NO_INCREMENT );
            return STATUS_DEVICE_NOT_READY;
        }

        const char* input = ( const char* ) irp->AssociatedIrp.SystemBuffer;
        ntlua_result* result = ( ntlua_result* ) irp->AssociatedIrp.SystemBuffer;

        size_t input_length = sp->Parameters.DeviceIoControl.InputBufferLength;
        size_t output_length = sp->Parameters.DeviceIoControl.OutputBufferLength;

        // Begin output size at 0.
        //
        irp->IoStatus.Information = 0;

        // If there is a valid, null-terminated buffer:
        //
        if ( input && input_length && input[ input_length - 1 ] == 0x0 )
        {
            // An optional chunk name may prefix the code as "name\0code\0";
            // when present it is used as the Lua chunk name so errors and
            // tracebacks report the real script path instead of "line".
            //
            const char* code = input;
            const char* chunkname = "line";
            size_t name_len = 0;
            while ( name_len < input_length && input[ name_len ] != 0 )
                name_len++;
            if ( name_len + 1 < input_length )
            {
                chunkname = input;
                code = input + name_len + 1;
            }

            // Copy the input into the request before spawning the thread: the
            // worker outlives this IRP on the timeout path and must never
            // touch SystemBuffer again once the IRP has completed.
            //
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

            // Bound the wait. On timeout the IRP completes while the worker
            // keeps running in the background; abort tells it to free its
            // request without touching this IRP.
            //
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

            // Export the captured output into user-mode memory; the worker
            // is parked on consumed_event and frees the buffers after this.
            //
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

                    }
                }

                return region;
            };

            if ( output_length >= sizeof( ntlua_result ) )
            {
                result->errors  = export_to_um( req->errors_copy );
                result->outputs = export_to_um( req->outputs_copy );
                irp->IoStatus.Information = sizeof( ntlua_result );
            }
            KeSetEvent( &req->consumed_event, IO_NO_INCREMENT, FALSE );
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
    else
    {
        // Report failure.
        //
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoReleaseRemoveLock( &remove_lock, irp );
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return STATUS_UNSUCCESSFUL;
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

    // Destroy the Lua context.
    //
    unique_lock _g{ LL };
    callback::run_teardown( L );
    callback::destroy( L );
    lua::destroy( L );
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

    // Initialize the VM lock before any IOCTL or callback can touch it.
    //
    LL.init();

    // Create a device object.
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

    // Initialize Lua.
    //
    L = lua::init();
    if ( !L )
    {
        IoDeleteSymbolicLink( &dos_device );
        IoDeleteDevice( device_object );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    lua::expose_api( L );

    // Initialize the universal callback bridge.
    //
    callback::init();
    callback::expose_api( L );
    return STATUS_SUCCESS;
}
