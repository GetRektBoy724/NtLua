-- test_gate.lua: gate.compile produces valid instruction streams.

T.test("gate.compile basic eq row", function()
    local prog = gate.compile{ { {arg=0, eq=0x1000} } }
    T.ok(type(prog) == "table" and #prog > 0, "returns a non-empty array")
end)

T.test("gate.compile with mask and range", function()
    local prog = gate.compile{ { {arg=2, mask=0xFF, range={0x10, 0x20}} } }
    T.ok(#prog >= 5, "has at least the 5-word program terminator")
end)

T.test("gate.compile stack+thread selectors", function()
    local prog = gate.compile{ { {stack=0x8, ge=1}, {thread=0x8, ne=0} } }
    T.ok(prog ~= nil)
end)

T.test("gate.compile rejects empty rows", function()
    T.err(function() gate.compile{} end, "empty")
end)

T.test("gate.compile rejects overflow program", function()
    local rows = {}
    for i = 1, 40 do
        rows[i] = { {arg=0, eq=1} }
    end
    T.err(function() gate.compile(rows) end, "exceeds")
end)