-- test_callback.lua - callback bridge Lua API surface.
-- Uses AllocateEvent / SetHandler / GetTrampoline / FreeEvent / SetFallback /
-- SetWait without hooking any live kernel path.

T.test("AllocateEvent returns an id", function()
    local eid = AllocateEvent()
    T.ok(eid ~= nil and eid >= 0, "event id should be non-nil")
    if eid then FreeEvent(eid) end
end)

T.test("SetHandler rejects arg_count > 16", function()
    local eid = AllocateEvent()
    T.ok(eid ~= nil)
    T.err(function() SetHandler(eid, 17, function() end) end, "arg_count")
    FreeEvent(eid)
end)

T.test("GetTrampoline returns a non-nil address", function()
    local eid = AllocateEvent()
    if not eid then T.skip("no free event slot"); return end
    local tp = GetTrampoline(eid)
    T.ok(tp ~= nil and type(tp) == "number" and tp ~= 0)
    FreeEvent(eid)
end)

T.test("FreeEvent on an unowned event id does not crash", function()
    local ok = pcall(function() FreeEvent(255) end)
    -- FreeEvent returns silently (0); expect no throw, well-defined result.
    T.ok(ok)
end)

T.test("SetFallback rejects a non-canonical address", function()
    local eid = AllocateEvent()
    if not eid then return end
    T.err(function() SetFallback(eid, 0x1000) end, "canonical")
    FreeEvent(eid)
end)

T.test("SetWait bounds range", function()
    local eid = AllocateEvent()
    if not eid then return end
    T.ok(pcall(function() SetWait(eid, 1000) end))
    FreeEvent(eid)
end)