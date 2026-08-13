-- ProcessMonitor.lua
-- Monitors process creation and exit using PsSetCreateProcessNotifyRoutine.

-- === Helpers ===

-- Print-friendly hex for addresses (kernel pointers are signed-int64 in Lua).
local function hex(v)
    if v == nil then return "nil" end
    return string.format("0x%016X", v & 0xFFFFFFFFFFFFFFFF)
end

local function read_cstring(addr)
    if addr == 0 then return "?" end
    local chars = {}
    for i = 0, 254 do
        local b = read1(addr + i)
        if b == 0 then break end
        chars[#chars + 1] = string.char(b)
    end
    return table.concat(chars)
end

local deref = nt.ObfDereferenceObject or nt.ObDereferenceObject
local proc_buf = tmp(8)

local function get_process_name(pid)
    if not nt.PsLookupProcessByProcessId or not nt.PsGetProcessImageFileName then
        return nil
    end
    proc_buf:set(0)
    local status = nt.PsLookupProcessByProcessId(pid, proc_buf:ref())
    if status ~= 0 then return nil end
    local eproc = proc_buf:get()
    if eproc == 0 then return nil end
    local name_ptr = nt.PsGetProcessImageFileName(eproc)
    local name = read_cstring(name_ptr)
    if deref then deref(eproc) end
    return name
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
    local status = nt.PsSetCreateProcessNotifyRoutine(tramp, 1)
    print(string.format("[stop] Process monitor deregistered: status=0x%08X", status & 0xFFFFFFFF))
    FreeEvent(eid)
    worker = nil
    print("Process monitor stopped (total callbacks: " .. callback_count .. ")")
end
