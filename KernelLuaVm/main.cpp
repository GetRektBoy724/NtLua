#include "crt/crt.h"
#include <ntifs.h>
#include <intrin.h>
#include "logger.hpp"
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

PEPROCESS attached_process = nullptr;
KAPC_STATE apc_state;

namespace lua
{
    static void begin_ctx()
    {
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
            }
        }
    }
    static void end_ctx()
    {
        __writecr8( 0 );
        _enable();
        if ( attached_process )
            KeUnstackDetachProcess( &apc_state );
    }

    bool detach()
    {
        if ( !attached_process )
            return false;
        KeUnstackDetachProcess( &apc_state );
        ObDereferenceObject( attached_process );
        attached_process = nullptr;
        return true;
    }
    bool attach_process( PEPROCESS process )
    {
        if ( ObReferenceObjectSafe( process ) )
        {
            detach();
            attached_process = process;
            KeStackAttachProcess( process, &apc_state );
            return true;
        }
        return false;
    }
    bool attach_pid( uint64_t pid )
    {
        PEPROCESS process = nullptr;
        PsLookupProcessByProcessId( ( HANDLE ) pid, &process );
        if ( !process ) 
            return false;

        detach();
        attached_process = process;
        KeStackAttachProcess( process, &apc_state );
        return true;
    }
};

// Device control handler.
//
NTSTATUS device_control( PDEVICE_OBJECT device_object, PIRP irp )
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation( irp );

    // Handle the command.
    //
    if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_RESET )
    {
        unique_lock _g{ LL };
        lua::destroy( L );
        L = lua::init();

        // A reset VM is useless without its API (the old code re-created a
        // bare state with no globals exposed).
        //
        lua::expose_api( L );
        callback::expose_api( L );
    }
    else if ( sp->Parameters.DeviceIoControl.IoControlCode == NTLUA_RUN )
    {
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

            struct captured_buffer
            {
                char*  data   = nullptr;
                size_t length = 0;
            };

            captured_buffer errors_copy, outputs_copy;

            // Snapshot the output under the VM lock, but keep the lock scope
            // as small as possible: exporting into user mode (below) does a
            // ZwAllocateVirtualMemory plus a copy, which must NOT hold LL -
            // otherwise every syscall callback that fires during that copy
            // misses the nonblocking gate.
            //
            {
                unique_lock _g{ LL };

                logger::errors.reset();
                logger::logs.reset();

                lua::begin_ctx();
                lua::execute( L, code, true, chunkname );
                lua::end_ctx();

                const auto capture = [ ] ( logger::string_buffer& buf ) -> captured_buffer
                {
                    captured_buffer out;
                    if ( buf.iterator )
                    {
                        out.data = ( char* ) malloc( buf.iterator + 1 );
                        if ( out.data )
                        {
                            memcpy( out.data, buf.raw, buf.iterator );
                            out.data[ buf.iterator ] = 0;
                            out.length = buf.iterator;
                        }
                    }
                    buf.reset();
                    return out;
                };

                errors_copy  = capture( logger::errors );
                outputs_copy = capture( logger::logs );
            }

            // Export the captured output into user-mode memory, outside LL.
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
                result->errors  = export_to_um( errors_copy );
                result->outputs = export_to_um( outputs_copy );
                irp->IoStatus.Information = sizeof( ntlua_result );
            }

            if ( errors_copy.data )  free( errors_copy.data );
            if ( outputs_copy.data ) free( outputs_copy.data );
        }
    }
    else
    {
        // Report failure.
        //
        irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest( irp, IO_NO_INCREMENT );
        return STATUS_UNSUCCESSFUL;
    }

    // Declare success and return.
    //
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

// Unloads the driver.
//
void unload_driver( PDRIVER_OBJECT driver )
{
    // Deactivate all callbacks (trampolines become no-ops).
    //
    callback::destroy();

    // Destroy the Lua context.
    //
    unique_lock _g{ LL };
    lua::destroy( L );

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
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

// Entry-point.
//
extern "C" NTSTATUS DriverEntry( DRIVER_OBJECT* DriverObject, UNICODE_STRING* RegistryPath )
{
    // Run static initializers.
    //
    crt::initialize();

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
    lua::expose_api( L );

    // Initialize the universal callback bridge.
    //
    callback::init();
    callback::expose_api( L );
    return STATUS_SUCCESS;
}