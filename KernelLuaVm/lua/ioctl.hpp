#pragma once

#include <ntifs.h>
#include "../driver_io.hpp"
#include "state.hpp"
#include "vm.hpp"

// Script-registered IOCTL handlers.
//
// A Lua script calls nt.register_ioctl(code, handler) at load time; when a
// user-mode process later calls DeviceIoControl(handle, code, ...) the driver
// routes it through the script's handler instead of the default
// STATUS_INVALID_DEVICE_REQUEST. The handler is handed the raw IRP and device
// object (handler(irp, device)) and manipulates them directly through the FFI;
// the driver still owns the IRP lifecycle and completes it after the handler
// returns, reading back irp->IoStatus.Status / Information. The handler must
// NOT call IoCompleteRequest - doing so double-completes the IRP (bugcheck
// 0x4B). Use nt.IoGetCurrentIrpStackLocation(irp) for the buffered input /
// output lengths and SystemBuffer.
//
// This is the user-to-kernel line: scripts author the behaviour at WDM
// dispatch granularity, the driver owns the IRP lifecycle. No trampoline/gate
// is needed (unlike the callback bridge) because IOCTLs fire at PASSIVE_LEVEL
// from device_control.
//
namespace ioctl
{
    constexpr int MAX_IOCTLS = 64;

    // Registry lifecycle.
    //
    void init();
    void begin_teardown();          // driver unload: drop all registrations
    void destroy( vm_instance* inst );  // instance destroy/reset: drop owner's

    // Expose register_ioctl / unregister_ioctl to a Lua state.
    //
    void expose_api( lua_State* L );

    // Registration (thread-safe). First-wins: an existing handler for a code
    // blocks a new one. Reserved NTLUA_* codes are rejected at registration.
    //
    bool register_ioctl( vm_instance* owner, uint32_t code, int lua_ref );
    bool unregister_ioctl( vm_instance* owner, uint32_t code );

    // Dispatch a non-built-in IOCTL IRP to the script handler. Sets a clean
    // default irp->IoStatus (SUCCESS / 0) before running the handler, then
    // completes the IRP with whatever the handler wrote. Does NOT release the
    // remove lock - the caller (device_control) does that, matching every
    // other branch.
    //
    void dispatch( PIRP irp, PIO_STACK_LOCATION sp );
}