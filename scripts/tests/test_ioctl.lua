-- test_ioctl.lua: script-registered IOCTL handler registry rules.
-- (Dispatch itself needs a user-mode caller; not covered here.)

T.test("CTL_CODE math", function()
    local c = CTL_CODE(0x13, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    T.eq(c, 0x132000)
end)

T.test("reserved NTLUA codes rejected", function()
    local reserved = {
        CTL_CODE(0x13, 0x39, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x3A, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x3B, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x3C, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x3D, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x3E, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x3F, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x40, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(0x13, 0x41, METHOD_BUFFERED, FILE_ANY_ACCESS),
    }
    for _, code in ipairs(reserved) do
        T.eq(register_ioctl(code, function() end), 0, "reserved code rejected")
    end
end)

T.test("register + unregister round-trip", function()
    local code = CTL_CODE(0x22, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
    T.eq(register_ioctl(code, function() return 0 end), 1)
    T.eq(unregister_ioctl(code), 1)
end)

T.test("register non-function rejected", function()
    local code = CTL_CODE(0x22, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
    T.eq(register_ioctl(code, 42), 0)
end)

T.test("first-wins collision", function()
    local code = CTL_CODE(0x22, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
    T.eq(register_ioctl(code, function() return 0 end), 1)
    T.eq(register_ioctl(code, function() return 0 end), 0, "second registration loses")
    T.eq(unregister_ioctl(code), 1)
end)
