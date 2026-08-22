-- test_memory.lua — read/write primitives and SEH containment.

local buf = tmp(32)

T.test("read/write byte round-trip", function()
    write1(buf:ref() + 0, 0xAB)
    T.eq(read1(buf:ref() + 0), 0xAB)
end)

T.test("read/write 16-bit round-trip", function()
    write2(buf:ref() + 2, 0xCDEF)
    T.eq(read2(buf:ref() + 2), 0xCDEF)
end)

T.test("read/write 32-bit round-trip", function()
    write4(buf:ref() + 4, 0x12345678)
    T.eq(read4(buf:ref() + 4), 0x12345678)
end)

T.test("read/write 64-bit round-trip", function()
    local v = 0xDEADBEEFCAFEBABE
    write8(buf:ref() + 8, v)
    T.eq(read8(buf:ref() + 8), v)
end)

-- SEH containment: reading a bad kernel pointer returns 0 instead of bugchecking.
T.test("read8 on invalid address returns 0 (SEH)", function()
    T.eq(read8(0x0000000041410000), 0, "read8 on unmapped low address should be 0")
end)

T.test("read1 on invalid address returns 0", function()
    T.eq(read1(0x0000000042420000), 0)
end)

-- NOTE: there is deliberately NO invalid-address WRITE test. Reads of
-- unmapped addresses are contained by the SEH guards, but writes are not
-- portable to test: (a) unmapped USER-range targets bugcheck 0x1A/0x4477
-- inside the MM fault resolver before any exception dispatch, and (b)
-- "read-only kernel page" targets only fault when the target config marks
-- them read-only (a test-signing VM with HVCI/KDP off let a header-page
-- write through silently). The invalid-read tests below already prove the
-- SEH plumbing works.


-- Boundary: every byte of a tmp() block is readable without faulting.
T.test("tmp() memory is readable at every offset", function()
    for i = 0, 31 do
        local v = read1(buf:ref() + i)
        T.ok(v >= 0 and v <= 0xFF)
    end
end)