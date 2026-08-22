-- test_struct.lua — struct.define field access and nested writes.

-- A struct type over a tmp() buffer.
local Point = struct.define{
    x = { offset = 0,  size = 4 },
    y = { offset = 4,  size = 4 },
    tag  = { offset = 8,  size = 1 },
    flag = { offset = 16, size = 8 },
}

T.test("struct scalar read/write", function()
    local p = Point(tmp(32):ref())
    p.x = 42
    p.y = 0xFFFFFF9F   -- write4 is unsigned; read4 returns unsigned
    p.tag = 0x7F
    p.flag = 0x1122334455667788
    T.eq(p.x, 42)
    T.eq(p.y, 0xFFFFFF9F)
    T.eq(p.tag, 0x7F)
    T.eq(p.flag, 0x1122334455667788)
end)

T.test("struct readable bytes", function()
    local p = Point(tmp(32):ref())
    T.ok(struct.read_bytes ~= nil)
    local bytes = struct.read_bytes(p:address(), 4)
    T.eq(#bytes, 4)
end)

T.test("nested struct field via type", function()
    local Inner = struct.define{ a = {0, 4}, b = {4, 4} }
    local Outer = struct.define{ inner = { 0, 8, type = Inner } }

    local o = Outer(tmp(16):ref())
    -- Can't write through a struct/ptr field, but reading returns the nested type
    -- bound to the correct offset.
    local inner = o.inner
    T.eq(inner:address(), o:address())
end)

-- Sub-field writes on a nested struct (the irp.IoStatus.Status pattern):
-- writing a nested struct's scalar sub-field must land at outer+field+suboff.
T.test("nested struct scalar sub-field write", function()
    local IoStatus = struct.define{ Status = {0x0, 4}, Information = {0x8, 8} }
    local Header = struct.define{ Type = {0x0, 4}, IoStatus = {0x8, 8, type = IoStatus} }

    local h = Header(tmp(32):ref())
    h.IoStatus.Status = 0xC0000001
    T.eq(read4(h:address() + 0x8), 0xC0000001, "Status lands at outer+0x8")
    h.IoStatus.Information = 0x40
    T.eq(read8(h:address() + 0x10), 0x40, "Information lands at outer+0x10")
end)