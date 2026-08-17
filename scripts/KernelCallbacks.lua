-- KernelCallbacks.lua
-- Enumerate kernel notify callbacks (DCMB-style) into a queryable structure.
-- Based on: /mnt/d/Desktop/DCMB (driver callback browser) and
--           RektsVDE-ImGui-AllNew/Features/DCMB + Disablers/kernel_callbacks.
--
-- Usage:  ntlua.exe scripts\KernelCallbacks.lua
--         -- prints a summary, then exposes the `callbacks` global table.
--
-- === Accessing the result ===
--
-- After the script runs, `callbacks` is a table keyed by callback type, each
-- value a list (array) of entries. The 8 types:
--   LoadImage, Process, Thread, ProcessObject, ThreadObject, DesktopObject,
--   Registry, DriverVerification
--
-- Every entry has these fields:
--   address   -- the callback function pointer (kernel VA)
--   entry     -- the array slot / list node address (for remove/restore)
--   fn_addr   -- the address of the function pointer itself (for hooking)
--   driver    -- owning module basename, e.g. "WdFilter.sys" ("unknown" if not found)
--   base      -- owning module image base (0 if unknown)
--   offset    -- address - base (the "driver+0xNNNN" RVA; 0 if unknown)
--   type      -- the type name, e.g. "Process" (set by enumerate_callbacks)
--   argc      -- callback argument count (for hook_callback's handler)
--   ret_width -- original return width (1/2/4/8)
--   version   -- "" / "Ex" / "Ex2" for array-based callbacks only
--   post      -- true/false for object callbacks only (pre- vs post-op)
--
-- Iterate / filter in the REPL:
--   for _, c in ipairs(callbacks.Process) do
--       if c.driver == "WdFilter.sys" then print(hex(c.address), c.version) end
--   end
--
-- Or use the helper for a flat, cross-type filter:
--   filter_callbacks(function(e)
--       return e.type == "Process" and e.driver == "WdFilter.sys"
--   end)
--
-- Note: hook_callback / remove_callback mutate the entry (hooked/removed
-- flags). Re-run enumerate_callbacks() to refresh the table from scratch.

-- === Helpers ===

local function hex(v)
    if v == nil then return "nil" end
    return string.format("0x%016X", v & 0xFFFFFFFFFFFFFFFF)
end

local function read_int32(addr)
    local v = read4(addr)
    if (v & 0x80000000) ~= 0 then return v - 0x100000000 end
    return v
end

local function basename(path)
    return path:match("([^\\]+)$") or path
end

-- Read a NUL-terminated ASCII string at addr (maxlen bytes).
local function read_cstr(addr, maxlen)
    local bytes = {}
    for i = 0, maxlen - 1 do
        local c = read1(addr + i)
        if c == 0 then break end
        bytes[#bytes + 1] = string.char(c)
    end
    return table.concat(bytes)
end

-- Resolve a kernel routine by name: export table first, then
-- MmGetSystemRoutineAddress (covers forwarded/non-exported names).
local function resolve(name)
    if nt[name] then return nt[name] end
    if nt.MmGetSystemRoutineAddress then
        local us = unicode_string(name)
        local addr = nt.MmGetSystemRoutineAddress(us:ref())
        if addr ~= 0 then
            nt[name] = native_function.new(addr)
            return nt[name]
        end
    end
    return nil
end

-- === Struct definitions ===

local LIST_ENTRY = struct.define {
    Flink = { 0x00, 8 },
    Blink = { 0x08, 8 },
}

local UNICODE_STRING = struct.define {
    Length        = { 0x00, 2 },
    MaximumLength = { 0x02, 2 },
    Buffer        = { 0x08, 8 },
}

local RTL_PROCESS_MODULE_INFORMATION = struct.define {
    ImageBase = { 0x10, 8 },
    ImageSize = { 0x18, 4 },
}

local EX_CALLBACK_ROUTINE_BLOCK = struct.define {
    RundownProtect = { 0x00, 8 },
    Function       = { 0x08, 8 },
    Flags          = { 0x10, 4 },
}

local REGISTRY_CALLBACK_ITEM = struct.define {
    Item     = { 0x00, 16, type = LIST_ENTRY },
    Function = { 0x28, 8 },
}

local OB_CALLBACK_ENTRY = struct.define {
    CallbackList  = { 0x00, 16, type = LIST_ENTRY },
    Enabled       = { 0x14, 1 },
    PreOperation  = { 0x28, 8 },
    PostOperation = { 0x30, 8 },
}

local CALLBACK_REGISTRATION = struct.define {
    Link             = { 0x00, 16, type = LIST_ENTRY },
    CallbackFunction = { 0x18, 8 },
}

local CLIENT_ID = struct.define {
    UniqueProcess = { 0x00, 8 },
    UniqueThread  = { 0x08, 8 },
}

local PS_CREATE_NOTIFY_INFO = struct.define {
    Size             = { 0x00, 8 },
    Flags            = { 0x08, 4 },
    ParentProcessId  = { 0x10, 8 },
    CreatingThreadId = { 0x18, 16, type = CLIENT_ID },
    FileObject       = { 0x28, 8 },
    ImageFileName    = { 0x30, 8, ptr = UNICODE_STRING },
    CommandLine      = { 0x38, 8, ptr = UNICODE_STRING },
    CreationStatus   = { 0x40, 4 },
}

-- Read a UNICODE_STRING struct instance into an ASCII string (preserves case,
-- drops non-ASCII chars).
local function read_wstring(us)
    if not us then return "" end
    local len = us.Length
    local buf = us.Buffer
    if buf == 0 or len == 0 then return "" end
    local out = {}
    local n = len // 2
    if n > 512 then n = 512 end
    for i = 0, n - 1 do
        local c = read2(buf + i * 2)
        if c == 0 then break end
        if c < 0x80 then out[#out + 1] = string.char(c) end
    end
    return table.concat(out)
end

-- === Module enumeration (ZwQuerySystemInformation 0x0B) ===
-- RTL_PROCESS_MODULE_INFORMATION is 0x128 bytes:
--   ImageBase @0x10, ImageSize @0x18, FullPathName @0x28 (CHAR[256]).

local modules = nil

local function enum_modules()
    if modules then return modules end

    local zqsi = resolve("ZwQuerySystemInformation")
    if not zqsi then
        print("[mod] ZwQuerySystemInformation not found")
        return nil
    end
    zqsi:ret_width(4)   -- NTSTATUS is 32-bit; mask the upper RAX bits

    local size_needed = tmp(4)
    local status = zqsi(0x0B, 0, 0, size_needed:ref())
    if status ~= 0xC0000004 then
        print("[mod] query size failed 0x" .. string.format("%08X", status & 0xFFFFFFFF))
        return nil
    end

    local size = read4(size_needed:ref())
    local buf = tmp(size + 0x1000)
    status = zqsi(0x0B, buf:ref(), size + 0x1000, size_needed:ref())
    if status ~= 0 then
        print("[mod] query failed 0x" .. string.format("%08X", status & 0xFFFFFFFF))
        return nil
    end

    local count = read4(buf:ref())
    local list = {}
    for i = 0, count - 1 do
        -- Modules[0] starts at offset 8 (ULONG NumberOfModules padded to
        -- 8-byte alignment for the PVOID MappedBase field).
        local m = RTL_PROCESS_MODULE_INFORMATION(buf:ref() + 8 + i * 0x128)
        list[#list + 1] = {
            base = m.ImageBase,
            size = m.ImageSize,
            path = read_cstr(m:address() + 0x28, 256),
        }
    end

    modules = list
    print("[mod] enumerated " .. count .. " modules")
    return list
end

-- Find the module containing addr; returns { base=, path=, name= } or nil.
local function find_module(addr)
    local list = enum_modules()
    if not list then return nil end
    for _, m in ipairs(list) do
        if addr >= m.base and addr < m.base + m.size then
            return { base = m.base, path = m.path, name = basename(m.path) }
        end
    end
    return nil
end

-- === Notify-array resolution (signature scanning) ===
-- The notify arrays (PspLoadImageNotifyRoutine, etc.) are not exported, so we
-- disassemble the public setter to find the internal array reference.

-- Find the first JMP/CALL (0xE9/0xE8) at addr, return the target.
local function follow_jmp_call(addr, maxlen)
    for i = 0, maxlen - 1 do
        local b = read1(addr + i)
        if b == 0xE9 or b == 0xE8 then
            return addr + i + 5 + read_int32(addr + i + 1)
        end
    end
    return nil
end

-- Find the first LEA (48 8D / 4C 8D) RIP-relative target at addr.
local function find_lea(addr, maxlen)
    for i = 0, maxlen - 1 do
        local b0 = read1(addr + i)
        local b1 = read1(addr + i + 1)
        if (b0 == 0x48 or b0 == 0x4C) and b1 == 0x8D then
            return addr + i + 7 + read_int32(addr + i + 3)
        end
    end
    return nil
end

-- Array-based types (LoadImage / Process / Thread): setter -> internal fn ->
-- LEA to the 64-entry notify array.
local function resolve_notify_array(setter_name)
    local setter = resolve(setter_name)
    if not setter then return nil end

    local psp = follow_jmp_call(setter:address(), 200)
    if not psp then return nil end

    return find_lea(psp, 300)
end

-- Object callbacks: PsProcessType / PsThreadType / ExDesktopObjectType are
-- exported pointers to OBJECT_TYPE; CallbackList is at +0xC8 (Win10 19045+).
local OBJECT_TYPE_CALLBACK_LIST_OFFSET = 0xC8

local function resolve_object_list(export_name)
    local var = nt[export_name]
    if not var then return nil end
    local obj_type = read8(var:address())
    if obj_type == 0 then return nil end
    return obj_type + OBJECT_TYPE_CALLBACK_LIST_OFFSET
end

-- Registry: CmRegisterCallback -> internal fn -> scan past the INT3 (0xCC)
-- padding -> LEA to CallbackListHead.
local function resolve_registry_list()
    local cm = resolve("CmRegisterCallback")
    if not cm then return nil end

    local psp = follow_jmp_call(cm:address(), 200)
    if not psp then return nil end

    local cmp_insert = nil
    for i = 0, 1023 do
        if read1(psp + i) == 0xCC then
            while read1(psp + i) == 0xCC do i = i + 1 end
            cmp_insert = psp + i
            break
        end
    end
    if not cmp_insert then return nil end

    for i = 0, 299 do
        if read1(cmp_insert + i) == 0x4C and read1(cmp_insert + i + 1) == 0x8D then
            return cmp_insert + i + 7 + read_int32(cmp_insert + i + 3)
        end
    end
    return nil
end

-- Driver verification: SeRegisterImageVerificationCallback -> forward MOV
-- (48 8B) to ExCbSeImageVerificationDriverInfo.
local function resolve_driver_verification()
    local se = resolve("SeRegisterImageVerificationCallback")
    if not se then return nil end

    local addr = se:address()
    for i = 0, 199 do
        if read1(addr + i) == 0x48 and read1(addr + i + 1) == 0x8B then
            return addr + i + 7 + read_int32(addr + i + 3)
        end
    end
    return nil
end

-- === Callback enumeration ===

-- EX_CALLBACK_ROUTINE_BLOCK: RundownProtect @0x00, Function @0x08, flags
-- DWORD @0x10. The array holds block pointers with the low 4 bits as flags.
-- The @0x10 flags encode an Ex variant, but per-family:
--   LoadImage: bit0 = Ex (still 3 args; flag only changes filtering semantics)
--   Process:   bit1 = Ex, bit2 = Ex2 (still 3 args; extended CreateInfo struct)
--   Thread:    no Ex variant
-- All three are always invoked with 3 arguments, so argc stays 3.
local function enum_array_callbacks(array_addr, kind)
    local result = {}
    for i = 0, 63 do
        local slot = array_addr + i * 8
        local entry = read8(slot)
        if entry ~= 0 then
            local block = EX_CALLBACK_ROUTINE_BLOCK(entry & ~0xF)
            local fn = block.Function
            if fn ~= 0 then
                local flags = block.Flags
                local version = ""
                if kind == "LoadImage" then
                    if (flags & 1) ~= 0 then version = "Ex" end
                elseif kind == "Process" then
                    if (flags & 4) ~= 0 then
                        version = "Ex2"
                    elseif (flags & 2) ~= 0 then
                        version = "Ex"
                    end
                end
                result[#result + 1] = {
                    address = fn, entry = slot, fn_addr = block:address() + 8,
                    argc = 3, ret_width = 8, version = version,
                }
            end
        end
    end
    return result
end

-- REGISTRY_CALLBACK_ITEM: Item (LIST_ENTRY) @0x00, Function @0x28.
-- Registry callback: NTSTATUS Cb(Context, Argument1, Argument2).
local function enum_registry_callbacks(list_head)
    local result = {}
    local current = read8(list_head)
    local seen = 0
    while current ~= 0 and current ~= list_head and seen < 256 do
        local item = REGISTRY_CALLBACK_ITEM(current)
        local fn = item.Function
        if fn ~= 0 then
            result[#result + 1] = {
                address = fn, entry = current, fn_addr = current + 0x28,
                argc = 3, ret_width = 4,
            }
        end
        current = item.Item.Flink
        seen = seen + 1
    end
    return result
end

-- OB_CALLBACK_ENTRY: CallbackList @0x00, PreOperation @0x28, PostOperation @0x30.
-- Pre: OB_PREOP_CALLBACK_STATUS Pre(RegistrationContext, PreInfo)
-- Post: VOID Post(RegistrationContext, PostInfo)
local function enum_object_callbacks(list_head)
    local result = {}
    local current = read8(list_head)
    local seen = 0
    while current ~= 0 and current ~= list_head and seen < 256 do
        local e = OB_CALLBACK_ENTRY(current)
        local pre = e.PreOperation
        local post = e.PostOperation
        if pre ~= 0 then
            result[#result + 1] = {
                address = pre, entry = current, fn_addr = current + 0x28,
                post = false, argc = 2, ret_width = 4,
            }
        end
        if post ~= 0 then
            result[#result + 1] = {
                address = post, entry = current, fn_addr = current + 0x30,
                post = true, argc = 2, ret_width = 8,
            }
        end
        current = e.CallbackList.Flink
        seen = seen + 1
    end
    return result
end

-- CALLBACK_OBJECT: RegisteredCallbacks @0x10. CALLBACK_REGISTRATION:
-- Link @0x00, CallbackFunction @0x18.
-- Driver verification: BOOLEAN Verify(Context, ...).
local function enum_driver_verification(array_addr)
    local result = {}
    local obj = read8(array_addr)
    if obj == 0 then return result end
    local head = obj + 0x10
    local current = read8(head)
    local seen = 0
    while current ~= 0 and current ~= head and seen < 256 do
        local reg = CALLBACK_REGISTRATION(current)
        local fn = reg.CallbackFunction
        if fn ~= 0 then
            result[#result + 1] = {
                address = fn, entry = current, fn_addr = current + 0x18,
                argc = 2, ret_width = 1,
            }
        end
        current = reg.Link.Flink
        seen = seen + 1
    end
    return result
end

-- === Main enumeration ===

-- Attach driver info (name/base/offset) to each callback entry.
local function annotate(entries)
    for _, e in ipairs(entries) do
        local m = find_module(e.address)
        if m then
            e.driver = m.name
            e.base = m.base
            e.offset = e.address - m.base
        else
            e.driver = "unknown"
            e.base = 0
            e.offset = 0
        end
    end
    return entries
end

-- Annotate with driver info and stamp the callback type (needed to pick the
-- right removal strategy).
local function finish(entries, type_name)
    annotate(entries)
    for _, e in ipairs(entries) do
        e.type = type_name
    end
    return entries
end

-- Return a flat list of callback entries matching `pred(e)` (across all types).
function filter_callbacks(pred)
    local result = {}
    for _, entries in pairs(callbacks) do
        for _, e in ipairs(entries) do
            if pred(e) then result[#result + 1] = e end
        end
    end
    return result
end

-- The queryable result, keyed by callback type.
callbacks = {
    LoadImage         = {},
    Process           = {},
    Thread            = {},
    ProcessObject     = {},
    ThreadObject      = {},
    DesktopObject     = {},
    Registry          = {},
    DriverVerification = {},
}

local TYPE_LABELS = {
    LoadImage          = "Image Load",
    Process            = "Process Creation",
    Thread             = "Thread Creation",
    ProcessObject      = "Process Object/Handle",
    ThreadObject       = "Thread Object/Handle",
    DesktopObject      = "Desktop Object/Handle",
    Registry           = "Registry RW",
    DriverVerification = "Driver Verification",
}

local TYPE_ORDER = {
    "LoadImage", "Process", "Thread",
    "ProcessObject", "ThreadObject", "DesktopObject",
    "Registry", "DriverVerification",
}

function enumerate_callbacks()
    -- Array-based types.
    callbacks.LoadImage = finish(enum_array_callbacks(
        resolve_notify_array("PsSetLoadImageNotifyRoutine") or 0, "LoadImage"), "LoadImage")
    callbacks.Process = finish(enum_array_callbacks(
        resolve_notify_array("PsSetCreateProcessNotifyRoutine") or 0, "Process"), "Process")
    callbacks.Thread = finish(enum_array_callbacks(
        resolve_notify_array("PsSetCreateThreadNotifyRoutine") or 0, "Thread"), "Thread")

    -- Object callbacks.
    callbacks.ProcessObject = finish(enum_object_callbacks(
        resolve_object_list("PsProcessType") or 0), "ProcessObject")
    callbacks.ThreadObject = finish(enum_object_callbacks(
        resolve_object_list("PsThreadType") or 0), "ThreadObject")
    callbacks.DesktopObject = finish(enum_object_callbacks(
        resolve_object_list("ExDesktopObjectType") or 0), "DesktopObject")

    -- Registry + driver verification.
    callbacks.Registry = finish(enum_registry_callbacks(
        resolve_registry_list() or 0), "Registry")
    callbacks.DriverVerification = finish(enum_driver_verification(
        resolve_driver_verification() or 0), "DriverVerification")

    return callbacks
end

function print_callbacks()
    local total = 0
    for _, type_name in ipairs(TYPE_ORDER) do
        local entries = callbacks[type_name]
        if #entries > 0 then
            total = total + #entries
            print("[" .. TYPE_LABELS[type_name] .. "] (" .. #entries .. ")")
            for _, e in ipairs(entries) do
                local op = ""
                if e.post ~= nil then
                    op = e.post and " post" or " pre"
                end
                local ver = ""
                if e.version and e.version ~= "" then
                    ver = " " .. e.version
                end
                print(string.format("    %-20s +0x%-8X  %s%s%s",
                    e.driver, e.offset, hex(e.address), op, ver))
            end
        end
    end
    print("")
    print("Total callbacks: " .. total)
end

-- === Removal / restore ===

removed = {}

local function is_array_type(t)
    return t == "LoadImage" or t == "Process" or t == "Thread"
end

local function is_object_type(t)
    return t == "ProcessObject" or t == "ThreadObject" or t == "DesktopObject"
end

-- Unlink a LIST_ENTRY-based callback. Every list type here (registry item,
-- OB_CALLBACK_ENTRY, CALLBACK_REGISTRATION) has its LIST_ENTRY at offset 0.
-- Returns the neighbors on success, nil if already unlinked.
local function unlink_entry(item)
    local le = LIST_ENTRY(item)
    local flink = le.Flink
    local blink = le.Blink
    if LIST_ENTRY(blink).Flink ~= item then
        return nil
    end
    LIST_ENTRY(blink).Flink = flink
    LIST_ENTRY(flink).Blink = blink
    return { flink = flink, blink = blink }
end

local function relink_entry(item, flink, blink)
    LIST_ENTRY(blink).Flink = item
    LIST_ENTRY(flink).Blink = item
end

-- Remove one callback: zeroes the array slot or unlinks the list node, and
-- records enough state to restore it. Returns true on success.
function remove_callback(e)
    if not e or e.removed then return false end
    local t = e.type
    if is_array_type(t) then
        local value = read8(e.entry)
        if value == 0 then return false end
        write8(e.entry, 0)
        e.saved = { kind = "slot", addr = e.entry, value = value }
    elseif is_object_type(t) then
        local s = unlink_entry(e.entry)
        if not s then return false end
        OB_CALLBACK_ENTRY(e.entry).Enabled = 0
        e.saved = { kind = "object", addr = e.entry, flink = s.flink, blink = s.blink }
    elseif t == "Registry" or t == "DriverVerification" then
        local s = unlink_entry(e.entry)
        if not s then return false end
        e.saved = { kind = "list", addr = e.entry, flink = s.flink, blink = s.blink }
    else
        return false
    end
    e.removed = true
    removed[#removed + 1] = e
    return true
end

-- Restore one removed callback. Returns true on success.
function restore_callback(e)
    if not e or not e.removed then return false end
    local s = e.saved
    if s.kind == "slot" then
        write8(s.addr, s.value)
    elseif s.kind == "list" then
        relink_entry(s.addr, s.flink, s.blink)
    elseif s.kind == "object" then
        relink_entry(s.addr, s.flink, s.blink)
        OB_CALLBACK_ENTRY(s.addr).Enabled = 1
    else
        return false
    end
    e.removed = false
    e.saved = nil
    return true
end

-- Remove all callbacks, optionally only those owned by `driver` (substring).
function remove_all(driver)
    local n = 0
    for _, entries in pairs(callbacks) do
        for _, e in ipairs(entries) do
            if not driver or (e.driver and e.driver:find(driver, 1, true)) then
                if remove_callback(e) then n = n + 1 end
            end
        end
    end
    return n
end

-- Restore all removed callbacks.
function restore_all()
    local n = 0
    for i = #removed, 1, -1 do
        if restore_callback(removed[i]) then
            n = n + 1
            table.remove(removed, i)
        end
    end
    return n
end

-- === Hooking / replacing ===

hooked = {}

-- Replace a callback's function pointer with a trampoline that dispatches to
-- the Lua function `fn`. The handler receives `argc` callback arguments
-- followed by three trap-time context values (thread, stack_base, rsp); its
-- return value becomes the callback's return value. When the VM cannot run
-- (elevated IRQL / lock busy), the original routine is invoked as a fallback.
function hook_callback(e, fn, argc)
    if not e or e.hooked then return false end

    local eid = AllocateEvent()
    if not eid then return false end

    local n = argc or e.argc or 3
    SetHandler(eid, n, fn)
    SetFallback(eid, e.address, e.ret_width or 8)

    local tramp = GetTrampoline(eid)
    if not tramp then
        FreeEvent(eid)
        return false
    end

    local patch = TrackPatch(e.fn_addr, tramp)
    if not patch then
        FreeEvent(eid)
        return false
    end
    e.orig = e.address
    e.eid = eid
    e.tramp = tramp
    e.patch = patch
    e.hooked = true
    hooked[#hooked + 1] = e
    return true
end

-- Restore a hooked callback's original function pointer and free the event.
function unhook_callback(e)
    if not e or not e.hooked then return false end
    local restored = RestorePatch(e.patch)
    FreeEvent(e.eid)
    e.hooked = false
    e.eid = nil
    e.tramp = nil
    e.patch = nil
    for i, x in ipairs(hooked) do
        if x == e then
            table.remove(hooked, i)
            break
        end
    end
    return restored
end

-- Restore all hooked callbacks.
function unhook_all()
    local n = 0
    local snapshot = hooked
    hooked = {}
    for _, e in ipairs(snapshot) do
        if unhook_callback(e) then n = n + 1 end
    end
    return n
end

OnTeardown(function()
    local ok, err = pcall(function()
        unhook_all()
        restore_all()
    end)
    if not ok then print("[teardown] callback restore failed: " .. tostring(err)) end
end)

-- === Run ===

enumerate_callbacks()
print_callbacks()
print("")
print("Removal API:")
print("  remove_callback(callbacks.Registry[1])   -- remove one")
print("  restore_callback(callbacks.Registry[1])  -- restore one")
print("  remove_all(\"WdFilter\")                  -- remove by driver")
print("  restore_all()                            -- restore all")
print("Hooking API:")
print("  hook_callback(e, fn [, argc])            -- replace with a Lua handler")
print("  unhook_callback(e)                       -- restore original")
print("  unhook_all()                             -- restore all hooks")

-- === Demo: hook WdFilter Ex2 process callback to deny notepad ===

local STATUS_ACCESS_DENIED = 0xC0000022

-- print() inside a callback writes to logger::logs, but that buffer is only
-- captured by a RUN IOCTL - and the next worker tick resets it before capture.
-- So the handler buffers events here, and worker() (invoked by the console
-- every tick) drains them.
proc_events = {}

local PROC_EVENTS_MAX = 256

local function push_event(s)
    if #proc_events < PROC_EVENTS_MAX then
        proc_events[#proc_events + 1] = s
    end
end

local function find_wdfilter_ex2()
    for _, e in ipairs(callbacks.Process) do
        if e.driver and e.driver:find("WdFilter", 1, true) and e.version == "Ex2" then
            return e
        end
    end
    return nil
end

local wd_ex2 = find_wdfilter_ex2()
if not wd_ex2 then
    print("[demo] no WdFilter Ex2 process callback found")
else
    hook_callback(wd_ex2, function(process, pid, create_info)
        if create_info == 0 then return 0 end   -- process exit: CreateInfo is NULL

        local info = PS_CREATE_NOTIFY_INFO(create_info)
        local ppid = info.ParentProcessId
        local tid  = info.CreatingThreadId.UniqueThread
        local name = read_wstring(info.ImageFileName)

        push_event(string.format("[proc] EPROCESS=%s pid=%s ppid=%s tid=%s name=%s",
            hex(process), pid, ppid, tid, name))

        if name:lower():find("notepad", 1, true) then
            push_event("[deny] blocking " .. name)
            info.CreationStatus = STATUS_ACCESS_DENIED
        end
        return 0
    end)
    print("[demo] hooked WdFilter Ex2 process callback")
end

function worker()
    local n = #proc_events
    for i = 1, n do
        print(proc_events[i])
    end
    for i = n, 1, -1 do
        table.remove(proc_events, i)
    end
end
