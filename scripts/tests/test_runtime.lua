-- test_runtime.lua - tmp()/string helpers from runtime.lua.

T.test("tmp() allocates and returns a non-zero ref", function()
    local b = tmp(16)
    T.ok(b:ref() ~= 0)
    T.eq(b.size, 16)
end)

T.test("tmp() get() reads back written bytes", function()
    local b = tmp(16)
    b:set(0x42, 0)      -- write 1 byte at offset 0
    T.eq(read1(b:ref() + 0), 0x42)
    b:set(0, 0)
    T.eq(b:get(0), 0)
end)

T.test("ansi_string packs a 2-byte length", function()
    local s = ansi_string("hello")
    T.eq(s.size, 0x10 + 5)
    -- write4 packs (len<<16 | len); the low 16 bits are the byte length
    T.eq(read2(s:ref()), 5)
end)

T.test("ansi_string content is copied at ref+0x10", function()
    local s = ansi_string("hey")
    T.eq(read1(s:ref() + 0x10), string.byte("h"))
    T.eq(read1(s:ref() + 0x11), string.byte("e"))
    T.eq(read1(s:ref() + 0x12), string.byte("y"))
end)