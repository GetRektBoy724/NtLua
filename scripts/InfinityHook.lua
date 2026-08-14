-- InfinityHook.lua
-- Complete InfinityHook implementation in Lua, using the universal callback bridge.
-- Based on: https://github.com/zhutingxf/InfinityHookPro
--
-- Usage:  ntlua.exe scripts\InfinityHook.lua
-- Then:   HookSyscall("NtCreateFile", function(a1,...) ... return 0 end)
--         UnhookAll() to stop

-- === Constants ===

local EtwpStartTrace   = 1
local EtwpStopTrace    = 2
local EtwpQueryTrace   = 3
local EtwpUpdateTrace  = 4

local EVENT_TRACE_FLAG_SYSTEMCALL = 0x00000080
local EVENT_TRACE_BUFFERING_MODE  = 0x00000400
local WNODE_FLAG_TRACED_GUID      = 0x00020000

local MAGIC_501802 = 0x501802
local MAGIC_601802 = 0x601802
local MAGIC_F33    = 0xF33    -- PerfInfo syscall ENTRY frame marker (swappable)
local MAGIC_F34    = 0xF34    -- PerfInfo syscall EXIT frame marker (dispatch already ran)

-- CKCL session GUID 54dea73a-ed1f-42a4-af71-3e63d056f174
-- (single source; used to START the trace and to detect stop attempts)
local CKCL_NAME     = "Circular Kernel Context Logger"
local CKCL_GUID_D1  = 0x54dea73a
local CKCL_GUID_W2  = 0xed1f
local CKCL_GUID_W3  = 0x42a4
local CKCL_GUID_LOW = 0x74f156d0633e71af   -- bytes: af 71 3e 63 d0 56 f1 74

-- True if a2 points at an EVENT_TRACE_PROPERTIES/WNODE carrying the CKCL GUID.
local function is_ckcl_props(a2)
    return read4(a2 + 0x18) == CKCL_GUID_D1 and
           read2(a2 + 0x1C) == CKCL_GUID_W2 and
           read2(a2 + 0x1E) == CKCL_GUID_W3 and
           read8(a2 + 0x20) == CKCL_GUID_LOW
end

-- === Helpers ===

-- Print-friendly hex for addresses (kernel pointers are signed-int64 in Lua).
local function hex(v)
    if v == nil then return "nil" end
    return string.format("0x%016X", v & 0xFFFFFFFFFFFFFFFF)
end

-- Return widths narrower than 32 bits for kernel routines: x64 only defines
-- AL/AX for 8/16-bit return values, so the upper RAX bits are undefined.
-- Applied to nt exports below and inside resolve_routine() (both paths).
local RET_WIDTHS = {
    ExGetPreviousMode = 1
}

local function read_int32(addr)
    local v = read4(addr)
    if (v & 0x80000000) ~= 0 then return v - 0x100000000 end
    return v
end

local function rip_relative(addr, insn_len, disp_off)
    return addr + insn_len + read_int32(addr + disp_off)
end

for name, w in pairs(RET_WIDTHS) do
    if nt[name] then nt[name]:ret_width(w) end
end

-- Resolve a kernel routine by name. Tries the nt export table first,
-- then falls back to MmGetSystemRoutineAddress (needed for NtTraceControl
-- which is not always in the export table / may be a forwarded export).
local function resolve_routine(name)
    if not nt[name] and nt.MmGetSystemRoutineAddress then
        local us = unicode_string(name)
        local addr = nt.MmGetSystemRoutineAddress(us:ref())
        if addr ~= 0 then
            nt[name] = native_function.new(addr)
        end
    end
    local fn = nt[name]
    if fn and RET_WIDTHS[name] then fn:ret_width(RET_WIDTHS[name]) end
    return fn
end

-- KTHREAD.PreviousMode offset (varies by Windows version). Found by
-- comparing read1(thread + offset) with ExGetPreviousMode().
local pm_off = nil

local function find_pm_off()
    if pm_off then return pm_off end
    local thread = read8(readgsbase() + 0x188)

    local expm = resolve_routine("ExGetPreviousMode")
    if not expm then
        print("[scan] ExGetPreviousMode not found")
        return nil
    end
    local pm = expm()
    print("[scan] PreviousMode value = " .. pm .. " (thread=" .. hex(thread) .. ")")

    for off = 0x00, 0x300 do
        if read1(thread + off) == pm then
            write1(thread + off, 0)
            if expm() == 0 then
                write1(thread + off, pm)
                pm_off = off
                print("[scan] PreviousMode at KTHREAD+0x" .. string.format("%X", off))
                return pm_off
            end
            write1(thread + off, pm)
        end
    end
    print("[scan] PreviousMode offset not found in range 0x00-0x300")
    return nil
end

-- Call a kernel function with PreviousMode temporarily set to KernelMode.
-- This bypasses ProbeForRead/ProbeForWrite on kernel-mode buffers.
local function call_as_kernel(fn, ...)
    local off = find_pm_off()
    if not off then return fn(...) end
    local thread = read8(readgsbase() + 0x188)
    local saved = read1(thread + off)
    write1(thread + off, 0)  -- KernelMode
    local result = fn(...)
    write1(thread + off, saved)
    return result
end

local function get_build_number()
    if not nt.RtlGetVersion then return 99999 end
    local buf = tmp(0x200)
    for _, sz in ipairs({0x11C, 0x114}) do
        write4(buf:ref(), sz)
        if nt.RtlGetVersion(buf:ref()) == 0 then
            return read4(buf:ref() + 0x0C)
        end
    end
    return 99999
end

-- ntoskrnl base + image size
local nt_base = nt.base_address:address()
local pe_off  = read4(nt_base + 0x3C)
local nt_size = read4(nt_base + pe_off + 24 + 0x38)
local build   = get_build_number()

print("[init] ntoskrnl=" .. hex(nt_base) .. " size=" .. nt_size .. " build=" .. build)

-- Section-scoped pattern scanner. Scans all non-discardable sections
-- (discarded sections like INIT have freed pages -> bugcheck 0x50).
local function find_pattern_safe(pattern, mask)
    local num_sections = read2(nt_base + pe_off + 6)
    local opt_size = read2(nt_base + pe_off + 20)
    local sec_table = nt_base + pe_off + 24 + opt_size
    for i = 0, num_sections - 1 do
        local s = sec_table + i * 40
        local flags = read4(s + 36)
        if (flags & 0x02000000) == 0 then  -- skip IMAGE_SCN_MEM_DISCARDABLE
            local vsize = read4(s + 8)
            local vaddr = read4(s + 12)
            local result = find_pattern(nt_base + vaddr, vsize, pattern, mask)
            if result then return result end
        end
    end
    return nil
end

-- === Step 1: Enable CKCL trace with syscall flag ===
-- Called directly from the script context (PASSIVE_LEVEL). The buffers come
-- from pool, so PreviousMode must be KernelMode or ETW's ProbeForRead/Write
-- rejects them: prefer ZwTraceControl (forces KernelMode internally), fall
-- back to NtTraceControl with call_as_kernel flipping PreviousMode.

local function resolve_trace_control()
    local zw = resolve_routine("ZwTraceControl")
    if zw then return zw, false end
    return resolve_routine("NtTraceControl"), true
end

-- CKCL_TRACE_PROPERTIES layout (verified by reversing ntoskrnl's
-- Etwp trace handling and cross-checking against the running kernel):
--   0x00 Wnode.BufferSize @0x00, Guid @0x18, ClientContext @0x28, Flags @0x2C
--   0x30 BufferSize / 0x34 MinimumBuffers / 0x38 MaximumBuffers
--   0x3C MaximumFileSize / 0x40 LogFileMode / 0x44 FlushTimer / 0x48 EnableFlags
--   0x4C..0x8F stats + LoggerThreadId / 0x90 ProviderName (UNICODE_STRING)
local function fill_ckcl_struct(b, enable_flags)
    memset(b, 0, 0x1000)

    write4(b + 0x00, 0x1000)
    write4(b + 0x18, CKCL_GUID_D1)
    write2(b + 0x1C, CKCL_GUID_W2)
    write2(b + 0x1E, CKCL_GUID_W3)
    write8(b + 0x20, CKCL_GUID_LOW)
    write4(b + 0x28, 3)
    write4(b + 0x2C, WNODE_FLAG_TRACED_GUID)

    write4(b + 0x30, 64)
    write4(b + 0x34, 8)
    write4(b + 0x38, 16)
    write4(b + 0x40, EVENT_TRACE_BUFFERING_MODE)
    if enable_flags then
        write4(b + 0x48, EVENT_TRACE_FLAG_SYSTEMCALL)
    end

    local nlen = #CKCL_NAME * 2
    local name_buf = tmp(128)
    memset(name_buf:ref(), 0, 128)
    local src = addressof(CKCL_NAME)
    for i = 0, #CKCL_NAME do
        write2(name_buf:ref() + i * 2, read1(src + i))
    end
    write2(b + 0x90, nlen)
    write2(b + 0x92, nlen + 2)
    write4(b + 0x94, 0)
    write8(b + 0x98, name_buf:ref())

    return name_buf
end

local function enable_ckcl()
    local ntc, needs_pm_flip = resolve_trace_control()
    if not ntc then
        print("[ckcl] ZwTraceControl/NtTraceControl not found")
        return false
    end
    print("[ckcl] Trace control = " .. (needs_pm_flip and "NtTraceControl" or "ZwTraceControl") ..
          " @ " .. hex(ntc:address()))

    local p = tmp(0x1000)
    local rl = tmp(4)

    local function call_trace(mode, name, flags)
        -- nb keeps the ProviderName buffer temp alive across the call
        -- (tmp() buffers are freed by __gc).
        local nb = fill_ckcl_struct(p:ref(), flags)
        local s = call_as_kernel(ntc, mode, p:ref(), 0x1000, p:ref(), 0x1000, rl:ref())
        print(string.format("[ckcl] %s status=0x%08X", name, s & 0xFFFFFFFF))
        return s, nb
    end

    if call_trace(EtwpUpdateTrace, "UpdateTrace", true) == 0 then
        print("[ckcl] CKCL trace already enabled!")
        return true
    end

    if call_trace(EtwpStartTrace, "StartTrace", false) ~= 0 then
        print("[ckcl] CKCL trace failed to start")
        return false
    end

    if call_trace(EtwpUpdateTrace, "UpdateTrace (enable)", true) ~= 0 then
        print("[ckcl] CKCL trace failed at enable step")
        return false
    end

    print("[ckcl] CKCL trace enabled successfully!")
    return true
end

if not enable_ckcl() then
    print("ERROR: Failed to enable CKCL trace")
    return
end

-- === Step 2: Find EtwpDebuggerData and walk to GetCpuClock ===

local etwp = find_pattern_safe("\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx")
if not etwp then print("ERROR: EtwpDebuggerData not found") return end

local silo    = read8(etwp + 0x10)
local ckcl    = read8(silo + 0x10)          -- silo[2]

local gcc_off = 0x18                        -- Win7 and Win11
if build > 7601 and build < 22000 then
    gcc_off = 0x28                          -- Win8 to Win10
end
local get_cpu_clock = ckcl + gcc_off        -- address of the GetCpuClock pointer

print("[scan] EtwpDebuggerData=" .. hex(etwp) .. " GetCpuClock=" .. hex(get_cpu_clock))

-- === Step 3: Resolve syscall entry page (for stack-walk range check) ===
-- LSTAR may point to a KVASCODE trampoline (Intel KVA shadow for Meltdown).
-- Follow the JMP (0xE9) to find the real KiSystemCall64.

local ki_syscall = readmsr(0xC0000082)

-- Scan first 32 bytes for a JMP rel32 (0xE9) - KVASCODE trampolines are short
for i = 0, 31 do
    if read1(ki_syscall + i) == 0xE9 then
        local target = ki_syscall + i + 5 + read_int32(ki_syscall + i + 1)
        if target ~= ki_syscall then
            ki_syscall = target
            break
        end
    end
end

local ssdt_page = ki_syscall & ~0xFFF

print("[scan] KiSystemCall64=" .. hex(ki_syscall) .. " syscall_page=" .. hex(ssdt_page))

-- SSDT base (data table), resolved lazily in HookSyscall.
local ssdt_base = nil

-- === Step 4: Win10 1909+ patterns (QPC path) ===

local use_qpc = (build > 18363)
local hvlp_tsc  = nil  -- HvlpReferenceTscPage
local hvl_bias  = nil  -- HvlGetQpcBias (address of the function-pointer global)
local hvlp_rt   = nil  -- HvlpGetReferenceTimeUsingTscPage

if use_qpc then
    hvlp_tsc = find_pattern_safe(
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
        "xxx????xxx?xxx????xxx")
    if hvlp_tsc then hvlp_tsc = rip_relative(hvlp_tsc, 7, 3) end

    hvl_bias = find_pattern_safe(
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74",
        "xxx????xxxx?xxx?????x")
    if not hvl_bias then
        hvl_bias = find_pattern_safe(
            "\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8\x48\x89\x1f",
            "xxx????x????xxxxxx")
    end
    if hvl_bias then hvl_bias = rip_relative(hvl_bias, 7, 3) end

    hvlp_rt = find_pattern_safe(
        "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x33\xc9\xe8\x00\x00\x00\x00\x48\x8b\xd8",
        "xxx????xxxx?xxx????xxx")
    if not hvlp_rt then
        hvlp_rt = find_pattern_safe(
            "\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8",
            "xxx????x????xxx")
    end
    if hvlp_rt then hvlp_rt = rip_relative(hvlp_rt, 7, 3) end

    print("[scan] HvlpRefTsc=" .. hex(hvlp_tsc) ..
          " HvlQpcBias=" .. hex(hvl_bias) ..
          " HvlpRefTime=" .. hex(hvlp_rt))

    if not hvl_bias then print("ERROR: HvlGetQpcBias not found") return end
end

-- === Step 5: QPC value helper ===

local function get_qpc()
    if hvlp_tsc then
        local page = read8(hvlp_tsc)
        if page ~= 0 then
            return read8(page + 24)  -- *(uint64*)(page + 3*8)
        end
    end
    return readtsc()
end

-- === Step 6: Per-syscall callback (SelfGetCpuClock / FakeHvlGetQpcBias) ===

local hooked = {}        -- [call_index] = {eid=, tramp=, name=, orig=}
local any_hooked = false

stats_gc = 0
stats_create_file = 0
stats_open_file = 0
stats_trace_control = 0

-- Walk-pipeline diagnostics: which stage does the syscall interception die in?
dbg_gc_indexed  = 0   -- KTHREAD index matched a hooked syscall
dbg_gc_walked   = 0   -- entered the stack walk
dbg_magic_dword = 0   -- 0x501802/0x601802 pattern seen on stack
dbg_magic_f33   = 0   -- syscall ENTRY frame marker (0xF33) - swappable
dbg_magic_f34   = 0   -- syscall EXIT frame marker (0xF34) - fires after dispatch, skip
dbg_gc_cand     = 0   -- return-address into KiSystemCall64 code page found
dbg_gc_swap     = 0   -- slot held our routine; swapped in the trampoline
dbg_gc_already  = 0   -- slot already held our trampoline (earlier swap won)
dbg_gc_miss     = 0   -- slot held neither; real miss
dbg_miss_val    = 0   -- last mismatched slot value (what's really there)
dbg_miss_orig   = 0   -- ... vs the routine address we expected
dbg_last_idx    = 0   -- syscall index that triggered the last walk

local ci_off = 0x80      -- KTHREAD.CallIndex offset (Win10+)
if build <= 7601 then ci_off = 0x1F8 end   -- Win7

local gc_eid = AllocateEvent()
if not gc_eid then print("ERROR: alloc event") return end

SetHandler(gc_eid, 0, function(thread, stack_base, rsp_trap)
    stats_gc = stats_gc + 1
    if not any_hooked then return get_qpc() end

    -- At DISPATCH_LEVEL (DPC/interrupt context) there is no syscall entry
    -- frame on this stack, and the magic values don't exist here.
    if readcr8() ~= 0 then return get_qpc() end

    -- thread/stack_base/rsp_trap were captured in the trampoline at trap
    -- time, before the VM lock was taken, so they stay consistent even if
    -- the thread migrated CPUs while waiting for the lock (gs is per-CPU;
    -- a stale gs resolves another CPU's KPCR - the old bugcheck 0x50).
    if stack_base <= rsp_trap then return get_qpc() end

    local idx = read4(thread + ci_off)
    if not hooked[idx] then return get_qpc() end
    dbg_gc_indexed = dbg_gc_indexed + 1
    dbg_last_idx = idx

    -- Skip kernel-mode callers
    if nt.ExGetPreviousMode and nt.ExGetPreviousMode() == 0 then
        return get_qpc()
    end

    -- PerfInfoLogSysCallEntry pushes the return address into KiSystemCall64
    -- onto the stack, so the candidate is a CODE address on the KiSystemCall64
    -- page (ssdt_page), NOT a pointer into the SSDT table.
    -- Marker 0xF33 = entry frame (swappable: dispatch hasn't happened yet);
    -- 0xF34 = exit frame (dispatch already ran - nothing to swap).
    -- The pSystemCallFunction slot (loaded into r10 just before `call rax`)
    -- sits 9 qwords past the candidate.
    --
    if not ssdt_base then return get_qpc() end
    dbg_gc_walked = dbg_gc_walked + 1

    local h = hooked[idx]

    local addr = stack_base - 8
    while addr > rsp_trap do
        local v = read4(addr)
        if v == MAGIC_501802 or v == MAGIC_601802 then
            dbg_magic_dword = dbg_magic_dword + 1
            local m = read2(addr - 8)
            if m == MAGIC_F34 then
                dbg_magic_f34 = dbg_magic_f34 + 1
            elseif m == MAGIC_F33 then
                dbg_magic_f33 = dbg_magic_f33 + 1

                local a2 = addr - 8
                while a2 < stack_base do
                    local cand = read8(a2)
                    local pg = cand & ~0xFFF
                    if pg >= ssdt_page and pg < ssdt_page + 0x2000 then
                        dbg_gc_cand = dbg_gc_cand + 1
                        local slotval = read8(a2 + 72)
                        if slotval == h.orig then
                            write8(a2 + 72, h.tramp)
                            dbg_gc_swap = dbg_gc_swap + 1
                            return get_qpc()
                        elseif slotval == h.tramp then
                            -- Already armed by an earlier timestamp of this
                            -- same call (e.g. its exit timestamp). The
                            -- topmost frame is always the innermost syscall,
                            -- which matches idx, so nothing deeper matters.
                            dbg_gc_already = dbg_gc_already + 1
                            return get_qpc()
                        else
                            dbg_gc_miss = dbg_gc_miss + 1
                            dbg_miss_val = slotval
                            dbg_miss_orig = h.orig
                        end
                        break
                    end
                    a2 = a2 + 8
                end
            end
        end
        addr = addr - 8
    end

    return get_qpc()
end, true)

local gc_tramp = GetTrampoline(gc_eid)
print("[hook] Trampoline = " .. hex(gc_tramp))

-- === Step 7: Overwrite GetCpuClock / HvlGetQpcBias ===

local orig_gcc = read8(get_cpu_clock)
local orig_bias = nil
local orig_rt  = nil
local rt_eid   = nil

if use_qpc then
    -- Set *GetCpuClock = 2 (magic value, forces HvlGetQpcBias path)
    write8(get_cpu_clock, 2)
    print("[hook] GetCpuClock = 2")

    -- Overwrite *HvlGetQpcBias with our trampoline. If the VM can't run
    -- (lock busy / elevated IRQL), forward to the original routine so the
    -- clock returns a real timestamp instead of 0.
    orig_bias = read8(hvl_bias)
    SetFallback(gc_eid, orig_bias, 8)
    write8(hvl_bias, gc_tramp)
    print("[hook] HvlGetQpcBias overwritten")

    -- Optionally overwrite HvlpGetReferenceTimeUsingTscPage if it's 0
    if hvlp_rt then
        orig_rt = read8(hvlp_rt)
        if orig_rt == 0 then
            local rt_eid_local = AllocateEvent()
            if rt_eid_local then
                SetHandler(rt_eid_local, 0, function() return readtsc() end, true)
                write8(hvlp_rt, GetTrampoline(rt_eid_local))
                rt_eid = rt_eid_local
                print("[hook] HvlpGetReferenceTimeUsingTscPage = rdtsc stub")
            end
        end
    end
else
    -- Win7 to Win10 1909: directly overwrite GetCpuClock
    SetFallback(gc_eid, orig_gcc, 8)
    write8(get_cpu_clock, gc_tramp)
    print("[hook] GetCpuClock overwritten")
end

print("")
print("=== InfinityHook active ===")
print("Hook syscalls with: HookSyscall(\"NtCreateFile\", function(a1,...) ... end)")
print("Stop with: UnhookAll()")
print("")

-- === Step 8: Self-healing + stats via worker ===

local last_gc, last_cf, last_of, last_tc = 0, 0, 0, 0

function worker()
    if stats_gc ~= last_gc or stats_create_file ~= last_cf or
       stats_open_file ~= last_of or stats_trace_control ~= last_tc then
        print("[stats] GetCpuClock=" .. stats_gc ..
              "  NtCreateFile=" .. stats_create_file ..
              "  NtOpenFile=" .. stats_open_file ..
              "  NtTraceControl=" .. stats_trace_control)
        last_gc, last_cf, last_of, last_tc =
            stats_gc, stats_create_file, stats_open_file, stats_trace_control

        print("[walk ] indexed=" .. dbg_gc_indexed .. " walked=" .. dbg_gc_walked ..
              " dword=" .. dbg_magic_dword .. " f33=" .. dbg_magic_f33 ..
              " f34=" .. dbg_magic_f34 .. " cand=" .. dbg_gc_cand ..
              " swap=" .. dbg_gc_swap .. " already=" .. dbg_gc_already ..
              " miss=" .. dbg_gc_miss .. " idx=" .. dbg_last_idx)
        if dbg_gc_miss ~= 0 then
            print("        miss slot=" .. hex(dbg_miss_val) ..
                  " expected orig=" .. hex(dbg_miss_orig))
        end
    end

    if use_qpc then
        if hvl_bias and read8(hvl_bias) ~= gc_tramp then
            write8(hvl_bias, gc_tramp)
            print("[heal] HvlGetQpcBias re-installed")
        end
        if get_cpu_clock and read8(get_cpu_clock) ~= 2 then
            write8(get_cpu_clock, 2)
            print("[heal] GetCpuClock re-set to 2")
        end
    else
        if get_cpu_clock and read8(get_cpu_clock) ~= gc_tramp then
            write8(get_cpu_clock, gc_tramp)
            print("[heal] GetCpuClock re-installed")
        end
    end
end

-- === Step 9: HookSyscall ===
-- Resolves the SSDT via a LEA inside KeRemoveSystemServiceTable,
-- then finds the syscall by scanning the SSDT.

local function resolve_ssdt()
    if ssdt_base then return ssdt_base end
    -- KeRemoveSystemServiceTable contains a LEA referencing KeServiceDescriptorTableFilter
    local krst = resolve_routine("KeRemoveSystemServiceTable")
    if not krst then
        print("[scan] KeRemoveSystemServiceTable not found")
        return nil
    end
    local krst_addr = krst:address()
    -- Scan for 48 8D (lea rax) or 4C 8D (lea r10) with RIP-relative addressing
    for i = 0, 299 do
        local b0 = read1(krst_addr + i)
        local b1 = read1(krst_addr + i + 1)
        if (b0 == 0x48 or b0 == 0x4C) and b1 == 0x8D then
            local disp = read_int32(krst_addr + i + 3)
            local target = krst_addr + i + 7 + disp
            ssdt_base = read8(target)
            if ssdt_base ~= 0 then
                print("[scan] SSDT base = " .. hex(ssdt_base))
                return ssdt_base
            end
        end
    end
    print("[scan] SSDT base not found via KeRemoveSystemServiceTable")
    return nil
end

function HookSyscall(name, fn)
    local exp = resolve_routine(name)
    if not exp then
        print("ERROR: " .. name .. " not found")
        return
    end
    local fn_addr = exp:address()

    local tbl = resolve_ssdt()
    if not tbl then
        print("ERROR: SSDT not resolved")
        return
    end

    -- SSDT entries are 4-byte signed offsets: routine = ssdt_base + (offset >> 4)
    local idx = nil
    for i = 0, 470 do
        local off = read_int32(tbl + i * 4)
        local routine = tbl + (off >> 4)
        if routine == fn_addr then
            idx = i
            break
        end
    end
    if not idx then
        print("ERROR: " .. name .. " not found in SSDT")
        return
    end

    local eid = AllocateEvent()
    if not eid then print("ERROR: alloc event") return end

    SetHandler(eid, 16, fn)

    hooked[idx] = { eid = eid, tramp = GetTrampoline(eid), name = name, orig = fn_addr }
    any_hooked = true

    print("[hook] " .. name .. " hooked (index " .. idx .. ")")
end

-- === Step 9b: Demo hooks (replicated from InfinityHookPro) ===

local STATUS_ACCESS_DENIED = 0xC0000022

local function read_wstring(addr, byte_len)
    if addr == 0 or byte_len == 0 then return "" end
    local chars = {}
    for i = 0, (byte_len / 2) - 1 do
        local c = read2(addr + i * 2)
        if c == 0 then break end
        chars[#chars + 1] = string.char(c)
    end
    return table.concat(chars)
end

-- OBJECT_ATTRIBUTES.ObjectName UNICODE_STRING -> name string (or "")
local function object_name(a3)
    if a3 == 0 then return "" end
    local obj_name = read8(a3 + 0x10)
    if obj_name == 0 then return "" end
    local name_buf = read8(obj_name + 0x08)
    local name_len = read2(obj_name + 0x00)
    if name_buf == 0 or name_len == 0 then return "" end
    return read_wstring(name_buf, name_len)
end

local function deny_test_txt(a3)
    local name = object_name(a3)
    if name == "" then return false end
    if string.find(name, "test.txt", 1, true) and
       not string.find(name, ".ini", 1, true) then
        print("[deny] file open attempt: " .. name)
        return true
    end
    return false
end

-- True for calls we never filter: elevated IRQL, kernel-mode callers,
-- or session-0 (system) processes.
local function hook_bypass()
    if readcr8() ~= 0 then return true end
    if nt.ExGetPreviousMode and nt.ExGetPreviousMode() == 0 then return true end
    if nt.PsGetProcessSessionId and nt.IoGetCurrentProcess then
        if nt.PsGetProcessSessionId(nt.IoGetCurrentProcess()) == 0 then return true end
    end
    return false
end

-- FakeNtCreateFile: deny access to files containing "test.txt" (but not ".ini")
-- 11 args: PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
--          PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG
HookSyscall("NtCreateFile", function(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
    stats_create_file = stats_create_file + 1
    if not hook_bypass() and deny_test_txt(a3) then
        return STATUS_ACCESS_DENIED
    end
    return nt.NtCreateFile(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
end)

-- FakeNtOpenFile: same deny for the open-only path (some callers use it
-- instead of NtCreateFile)
-- 6 args: PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
--         ULONG OpenOptions, ULONG
HookSyscall("NtOpenFile", function(a1, a2, a3, a4, a5, a6)
    stats_open_file = stats_open_file + 1
    if not hook_bypass() and deny_test_txt(a3) then
        return STATUS_ACCESS_DENIED
    end
    return nt.NtOpenFile(a1, a2, a3, a4, a5, a6)
end)

-- FakeNtTraceControl: deny stopping the CKCL trace
-- 6 args: ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen,
--         PVOID OutBuffer, ULONG OutBufferLen, PULONG ReturnLength
HookSyscall("NtTraceControl", function(a1, a2, a3, a4, a5, a6)
    stats_trace_control = stats_trace_control + 1
    if not hook_bypass() and a1 == EtwpStopTrace and a2 ~= 0 and is_ckcl_props(a2) then
        print("[deny] NtTraceControl: attempt to stop CKCL trace")
        return STATUS_ACCESS_DENIED
    end
    return nt.NtTraceControl(a1, a2, a3, a4, a5, a6)
end)

print("[hook] NtCreateFile + NtOpenFile + NtTraceControl hooks registered")

-- === Step 10: UnhookAll ===

function UnhookAll()
    -- Unregister all syscall hooks
    for idx, h in pairs(hooked) do
        FreeEvent(h.eid)
        hooked[idx] = nil
    end
    any_hooked = false

    -- Restore originals
    if use_qpc then
        if rt_eid then FreeEvent(rt_eid) end
        if orig_rt ~= nil and orig_rt == 0 and hvlp_rt then
            write8(hvlp_rt, orig_rt)
        end
        if orig_bias and hvl_bias then
            write8(hvl_bias, orig_bias)
        end
        print("[stop] Restored HvlGetQpcBias + GetCpuClock")
    end
    write8(get_cpu_clock, orig_gcc)

    FreeEvent(gc_eid)
    worker = nil
    print("[stop] InfinityHook stopped")
end
