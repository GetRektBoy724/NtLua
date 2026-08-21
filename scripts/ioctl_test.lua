-- ioctl_test.lua : register a script-authored IOCTL handler.
--
-- handler(irp, device) receives the raw IRP and device object (x64 Win10/11
-- layout below). The handler manipulates the IRP through the struct library
-- and read/write primitives; the driver completes the IRP after it returns,
-- reading back irp->IoStatus.{Status,Information}. Do NOT call
-- IoCompleteRequest here - that double-completes the IRP (bugcheck 0x4B).

local IO_STATUS_BLOCK = struct.define {
    Status      = { 0x00, 4 },   -- NTSTATUS
    Information = { 0x08, 8 },   -- bytes written
}

local IRP = struct.define {
    Type           = { 0x00, 2 },
    Size           = { 0x02, 2 },
    MdlAddress     = { 0x08, 8 },
    Flags          = { 0x10, 4 },
    SystemBuffer   = { 0x18, 8 },  -- AssociatedIrp.SystemBuffer (METHOD_BUFFERED)
    IoStatus       = { 0x30, 0x10, type = IO_STATUS_BLOCK },
}

-- Parameters union member for NtDeviceIoControlFile (union at IO_STACK+0x08).
--
local DEVICE_IO_CONTROL = struct.define {
    OutputBufferLength = { 0x00, 4 },
    InputBufferLength  = { 0x08, 4 },
    IoControlCode      = { 0x10, 4 },
    Type3InputBuffer   = { 0x18, 8 },
}

local IO_STACK_LOCATION = struct.define {
    MajorFunction   = { 0x00, 1 },
    MinorFunction   = { 0x01, 1 },
    Flags           = { 0x02, 1 },
    Control         = { 0x03, 1 },
    DeviceIoControl = { 0x08, 0x20, type = DEVICE_IO_CONTROL },
    DeviceObject    = { 0x28, 8 },
    FileObject      = { 0x30, 8 },
}

local IOCTL_ECHO = CTL_CODE( 0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )

-- Reverse the input bytes in SystemBuffer and complete with SUCCESS.
--
local function echo_handler( irp_addr, device_addr )
    local irp = IRP( irp_addr )
    -- IRP.CurrentStackLocation is at +0xB8 (same offset the kernel's
    -- IoGetCurrentIrpStackLocation inline reads). Reading it directly avoids
    -- a dependency on that function being present in the nt export table.
    --
    print("[ioctl_test] ioctl echo handler triggered!")
    local sp = IO_STACK_LOCATION( read8( irp_addr + 0xB8 ) )

    local buf     = irp.SystemBuffer
    local in_len  = sp.DeviceIoControl.InputBufferLength
    local out_cap = sp.DeviceIoControl.OutputBufferLength
    local cap     = out_cap < in_len and out_cap or in_len

    if buf ~= 0 and cap > 0 then
        local bytes = {}
        for i = 0, cap - 1 do
            bytes[ i + 1 ] = read1( buf + i )
        end
        for i = 1, cap do
            write1( buf + i - 1, bytes[ cap - i + 1 ] )
        end
        irp.IoStatus.Information = cap
    else
        irp.IoStatus.Information = 0
    end
    irp.IoStatus.Status = 0    -- STATUS_SUCCESS
end

if register_ioctl( IOCTL_ECHO, echo_handler ) ~= 1 then
    print( "[ioctl_test] register_ioctl failed for 0x" .. string.format( "%X", IOCTL_ECHO ) )
    return
end
print( ( "[ioctl_test] armed 0x%X (send 'ABCD' -> 'DCBA' back)" ):format( IOCTL_ECHO ) )

-- Revert: unregister the handler, and re-arm it by re-running the script.
-- The teardown below makes this automatic on reset/kill, so a stale handler
-- can never outlive the instance that owns it.
--
local function revert_ioctl_test()
    if unregister_ioctl( IOCTL_ECHO ) ~= 1 then
        print( "[ioctl_test] not armed (0x" .. string.format( "%X", IOCTL_ECHO ) .. ")" )
        return
    end
    print( "[ioctl_test] unregistered 0x" .. string.format( "%X", IOCTL_ECHO ) )
end
_G.revert_ioctl_test = revert_ioctl_test

-- Automatic cleanup: when the instance is reset or destroyed the callback
-- bridge runs this, so the handler is dropped with the instance instead of
-- lingering in the global ioctl registry.
--
if OnTeardown then
    OnTeardown( revert_ioctl_test )
end