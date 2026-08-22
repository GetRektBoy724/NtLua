-- Regression-test harness for NtLua.
--
-- Loaded once per session with `load scripts\tests\framework.lua`; it defines
-- a global `T` table that persists across REPL chunks on the same instance.
-- Test files then call:
--
--     T.test("name", function()
--         T.eq(a, b)          -- fail unless a == b
--         T.ok(cond, "msg")   -- fail unless cond
--         T.err(fn, pat)      -- fail unless calling fn() raises an error matching pat (Lua pattern)
--         T.skip()            -- mark the case skipped (e.g. not supported on this instance)
--     end)
--
-- The function is run via pcall: any error it raises (from T.eq / T.err /
-- T.fail, or an uncaught runtime error) is counted as a failure. Successful
-- cases advance T.pass. T.summary() prints a count and returns the pass count
-- (0 on any failure) so a runner can detect a clean run.

T = {}
T.pass = 0
T.fail = 0
T.skipped = 0
T._current = nil

local function record(ok, name, msg)
    if ok then
        T.pass = T.pass + 1
        print(("[PASS] %s"):format(name))
    else
        T.fail = T.fail + 1
        print(("[FAIL] %s  %s"):format(name, msg or ""))
    end
end

function T.test(name, thunk)
    if T._current then
        error("nested T.test is not allowed", 2)
    end
    T._current = name
    local ok, err = pcall(thunk)
    T._current = nil
    if ok then
        record(true, name, nil)
    else
        record(false, name, err)
    end
end

function T.ok(cond, msg)
    if not cond then
        print(("   assert: %s"):format(msg or "expected truthy"))
        error("assertion failed: " .. tostring(msg or "?"), 2)
    end
end

function T.eq(a, b, msg)
    local astr, bstr = tostring(a), tostring(b)
    if type(a) ~= type(b) then
        print(("   assert: %s (type %s != %s)"):format(msg or "", type(a), type(b)))
        error("assertion failed: " .. tostring(msg or "?"))
    end
    if astr ~= bstr then
        print(("   assert: %s: %s != %s"):format(msg or "eq", astr, bstr))
        error("assertion failed: " .. (msg or "eq"), 2)
    end
end

function T.ne(a, b, msg)
    if tostring(a) == tostring(b) then
        print(("   assert: %s: %s == %s"):format(msg or "ne", tostring(a), tostring(b)))
        error("assertion failed: " .. (msg or "ne"), 2)
    end
end

-- T.err(fn, pattern) runs fn() expecting a Lua error whose message matches pat
-- (as a Lua string.find pattern). Passes if it errors and matches; fails otherwise.
function T.err(fn, pat)
    local ok, err = pcall(fn)
    if ok then
        error("expected an error but fn() succeeded", 2)
    end
    if pat and not string.find(err or "", pat, 1, true) then
        error(("expected error matching '%s', got '%s'"):format(pat, tostring(err)))
    end
end

function T.skip(reason)
    T.skipped = T.skipped + 1
    print(("  [skip] %s"):format(reason or "skipped"))
end

function T.summary()
    print(("RESULT %d pass, %d fail, %d skipped"):format(T.pass, T.fail, T.skipped))
    return T.fail == 0
end