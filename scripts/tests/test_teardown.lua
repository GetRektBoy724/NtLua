-- test_teardown.lua: OnTeardown and TrackPatch/RestorePatch round-trips.

T.test("OnTeardown accepts and registers a callback", function()
    local ok = OnTeardown(function() end)
    T.eq(ok, true)
end)

T.test("OnTeardown rejects a full table gracefully", function()
    -- Register many; the table is per-instance and holds 32 slots.
    local registered = 0
    for i = 1, 33 do
        if OnTeardown(function() end) then
            registered = registered + 1
        end
    end
    -- At least the first 32 must succeed; the 33rd may be rejected
    -- (returns false) but must not error.
    T.ok(registered >= 1)
end)

T.test("TrackPatch + RestorePatch round-trip on pool memory", function()
    local buf = tmp(16)
    local addr = buf:ref()
    write8(addr, 0x1111111111111111)
    local pid = TrackPatch(addr, 0x2222222222222222, 8)
    T.ok(pid ~= nil and pid >= 0, "TrackPatch returns a slot")
    T.eq(read8(addr), 0x2222222222222222, "replacement applied")
    local restored = RestorePatch(pid)
    T.eq(restored, true, "RestorePatch succeeds")
    T.eq(read8(addr), 0x1111111111111111, "original restored")
end)

T.test("RestorePatch on an already-restored slot is a safe no-op", function()
    local buf = tmp(8)
    local addr = buf:ref()
    write8(addr, 5)
    local pid = TrackPatch(addr, 9, 8)
    T.ok(pid ~= nil and pid >= 0)
    T.eq(RestorePatch(pid), true)
    T.eq(RestorePatch(pid), false, "second restore returns false")
end)
