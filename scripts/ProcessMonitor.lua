-- ProcessMonitor.lua
-- Monitors process creation and exit using PsSetCreateProcessNotifyRoutine.

-- === Helpers ===

-- Print-friendly hex for addresses (kernel pointers are signed-int64 in Lua).
local function hex(v)
    if v == nil then return "nil" end
    return string.format("0x%016X", v & 0xFFFFFFFFFFFFFFFF)
end

local deref = nt.ObfDereferenceObject or nt.ObDereferenceObject
local proc_buf = tmp(8)

-- SeLocateProcessImageName returns a full UNICODE_STRING path (e.g.
-- "\Device\HarddiskVolume3\Windows\System32\OpenConsole.exe"). We cannot use
-- PsGetProcessImageFileName: it reads the fixed 15-byte EPROCESS.ImageFileName
-- buffer, so names longer than 14 chars come back truncated (e.g.
-- "OpenConsole.ex"). SeLocateProcessImageName allocates the UNICODE_STRING with
-- ExAllocatePoolWithTag; the caller must free it.
--
local UNICODE_STRING = struct.define {
    Length        = { 0x00, 2 },
    MaximumLength = { 0x02, 2 },
    Buffer        = { 0x08, 8 },
}

local function get_process_name(pid)
    if not nt.PsLookupProcessByProcessId or not nt.SeLocateProcessImageName then
        return nil
    end
    proc_buf:set(0)
    local status = nt.PsLookupProcessByProcessId(pid, proc_buf:ref())
    if status ~= 0 then return nil end
    local eproc = proc_buf:get()
    if eproc == 0 then return nil end

    local unicode_ptr = tmp(8)
    unicode_ptr:set(0)
    status = nt.SeLocateProcessImageName(eproc, unicode_ptr:ref())
    if deref then deref(eproc) end
    if status ~= 0 then return nil end

    local us = UNICODE_STRING( unicode_ptr:get() )
    if not us then return nil end
    local len = us.Length
    local buf = us.Buffer
    if buf == 0 or len == 0 then return nil end

    local chars = {}
    for i = 0, (len // 2) - 1 do
        local w = read2(buf + i * 2)
        if w == 0 then break end
        chars[#chars + 1] = string.char(w & 0xFF)   -- ASCII-compatible path chars
    end
    free(buf)
    return table.concat(chars)
end

-- === State ===

local events = {}
callback_count = 0

-- === Register ===

if not nt.PsSetCreateProcessNotifyRoutine then
    print("ERROR: PsSetCreateProcessNotifyRoutine not in nt table")
    return
end

local eid = AllocateEvent()
if not eid then
    print("ERROR: Failed to allocate event slot")
    return
end

-- The bridge also appends the trap-time context values (thread, stack_base,
-- rsp) after the declared args; undeclared parameters simply drop them.
SetHandler(eid, 3, function(parent_pid, pid, create)
    callback_count = callback_count + 1
    -- BOOLEAN is 1 byte but the trampoline captures 8 bytes from R8;
    -- mask to the low byte before testing.
    if (create & 0xFF) ~= 0 then
        local name = get_process_name(pid) or "?"
        local pname = get_process_name(parent_pid) or "?"
        events[#events + 1] = "[+] " .. name .. "  PID=" .. pid ..
                              "  parent=" .. pname .. "  PPID=" .. parent_pid
    else
        local name = get_process_name(pid)
        if name then
            events[#events + 1] = "[-] " .. name .. "  PID=" .. pid .. " exited"
        else
            events[#events + 1] = "[-] PID=" .. pid .. " exited"
        end
    end
end)

local tramp = GetTrampoline(eid)
print("Event ID: " .. eid .. "  Trampoline: " .. hex(tramp))

local status = nt.PsSetCreateProcessNotifyRoutine(tramp, 0)
if status ~= 0 then
    print(string.format("ERROR: Registration failed: status=0x%08X", status & 0xFFFFFFFF))
    FreeEvent(eid)
    return
end

print("Process monitor active.")
print("Try launching a process (e.g. type 'cmd' here).")
print("Call StopProcessMonitor() to stop.")

local active = true

-- === Worker ===

local last_count = 0

function worker()
    if callback_count ~= last_count or #events > 0 then
        print("[stats] callbacks=" .. callback_count .. " events=" .. #events)
        last_count = callback_count
    end
    for i = 1, #events do
        print(events[i])
    end
    events = {}
end

-- === Cleanup ===

function StopProcessMonitor()
    if not active then return false end
    active = false
    local status = nt.PsSetCreateProcessNotifyRoutine(tramp, 1)
    print(string.format("[stop] Process monitor deregistered: status=0x%08X", status & 0xFFFFFFFF))
    FreeEvent(eid)
    worker = nil
    print("Process monitor stopped (total callbacks: " .. callback_count .. ")")
    return status == 0
end

OnTeardown(function()
    if active then
        local ok, err = pcall(StopProcessMonitor)
        if not ok then print("[teardown] Process monitor restore failed: " .. tostring(err)) end
    end
end)
