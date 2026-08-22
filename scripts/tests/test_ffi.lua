-- test_ffi.lua - native_function FFI behavior.

T.test("native_function.new returns callable", function()
    local fn = native_function.new(nt.KeGetCurrentIrql:address())
    T.ok(fn ~= nil)
end)

T.test("ret_width validation rejects bad widths", function()
    local fn = native_function.new(nt.KeGetCurrentIrql:address())
    T.err(function() fn:ret_width(3) end, "ret_width")
end)

T.test("call a real export with width masking", function()
    local irql = nt.KeGetCurrentIrql()
    -- KeGetCurrentIrql returns a 1-byte KIRQL; without masking upper RAX bits
    -- could be stale, but the driver's FFI masks for the registered width (8 by
    -- default here). Assert IRQL is a sane 0..31 value.
    T.ok(irql <= 31 and irql >= 0, "got irql=" .. tostring(irql))
end)

T.test("32-argument cap errors cleanly", function()
    local fn = native_function.new(nt.KeGetCurrentIrql:address())
    -- Far too many args is an error at dispatch, not a crash.
    local ok, err = pcall(function() fn(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33) end)
    T.ok(not ok)
end)