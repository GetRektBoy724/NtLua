# NtLua Reference Manual

NtLua is a Windows kernel driver that embeds Lua 5.3. A user-mode console
sends Lua source to the driver; the driver executes it in a kernel-resident
Lua state and returns captured output and errors.

NtLua is a kernel research and reverse-engineering tool. It exposes raw
memory access, physical memory access, privileged CPU operations, arbitrary
calls through imported kernel exports, callback replacement, and kernel
structure mutation. It is not a normal production security boundary.

## Contents

- [Architecture](#architecture)
- [Build and Load](#build-and-load)
- [Execution and Lifecycle](#execution-and-lifecycle)
- [Lua API](#lua-api)
- [Native Function Interface](#native-function-interface)
- [Runtime Libraries](#runtime-libraries)
- [Callback Bridge](#callback-bridge)
- [Admission Gates](#admission-gates)
- [Tracked Patches](#tracked-patches)
- [Shipped Scripts](#shipped-scripts)
- [Safety Rules](#safety-rules)
- [Troubleshooting](#troubleshooting)

## Architecture

The repository contains four principal pieces:

```text
ActualConsole/        User-mode console (ntlua.exe)
KernelLuaVm/          Kernel driver (KernelLuaVm.sys)
LuaLib/               Lua 5.3 library compiled for the driver
scripts/              Lua utilities and demonstrations
```

The normal execution path is:

```text
ntlua.exe
    -> \Device\NtLua
    -> NTLUA_RUN IOCTL
    -> driver input parser
    -> lua::execute()
    -> Lua API / script
    -> logger::logs and logger::errors
    -> user-mode output buffers
```

The driver owns one shared `lua_State`. Lua execution is serialized by `LL`,
a kernel mutex with owner tracking. Callback trampolines capture their raw
arguments and trap-time context before dispatching into the VM.

The source is arranged as follows:

```text
KernelLuaVm/
  main.cpp                 DriverEntry, IOCTLs, VM lifecycle
  lua/
    api.cpp                Built-in Lua API exports
    callback.cpp           Callback bridge, gates, patches, teardown
    callback.hpp           VM lock and callback declarations
    native_function.cpp    Native-function userdata invocation
    native_function.hpp
    state.cpp              Lua allocator, panic, execute, traceback
    state.hpp
  runtime/
    runtime.lua            Temporary buffers and string wrappers
    struct.lua             Offset-based structure library
    gate.lua               Admission-gate compiler
  crt/                     Kernel-compatible C runtime support
  trampolines.inc          256 compile-time trampoline instantiations
```

## Build and Load

Build the solution with Visual Studio 2022 and the Windows Driver Kit:

```text
NtLua.sln
Configuration: Release
Platform: x64
```

The driver is built as `KernelLuaVm.sys` and signed by the project build
configuration.

Create and start the service from an elevated command prompt:

```text
sc create NtLua binpath= C:\path\to\KernelLuaVm.sys type= kernel
sc start NtLua
```

Then run the console:

```text
x64\Release\ntlua.exe
```

Stop the service only after restoring any externally installed hooks:

```text
sc stop NtLua
```

Scripts that use `OnTeardown` and `TrackPatch` restore their registered
changes automatically during reset and unload, but raw writes made by an
arbitrary script remain the script author's responsibility.

## Execution and Lifecycle

### `NTLUA_RUN`

`NTLUA_RUN` is a buffered IOCTL. The console normally sends one of these
payloads:

```text
script-name\0lua-source\0
```

The driver splits the first NUL-separated field into the Lua chunk name. The
chunk name appears in parser errors and stack tracebacks. If no name prefix is
present, the fallback name is `line`.

The driver resets the logger buffers at the beginning of a run, executes the
chunk, copies the error/output buffers into the caller's address space, and
completes the IRP.

The console's `print()` output is captured in the output buffer. Runtime and
parser failures are captured in the error buffer.

### `NTLUA_RESET`

Reset performs an ordered VM reset:

1. Stop accepting new callback dispatches.
2. Wait for in-flight callback trampolines through rundown protection.
3. Run registered `OnTeardown` callbacks while the old Lua state is valid.
4. Restore tracked patches and clear callback references.
5. Destroy the old Lua state.
6. Create a new Lua state and expose all built-ins again.

Hooks do not survive reset. Scripts must install them again after reset.

### Driver unload

Unload performs the same teardown sequence, in addition to waiting for all
in-flight create/close/device-control IRPs through an `IO_REMOVE_LOCK` before
destroying the VM and device object.

The callback rundown prevents callback code from running while the driver is
being destroyed. `OnTeardown` and tracked patches address the separate issue
of kernel data structures retaining pointers into the driver image.

### Panic and exception behavior

Lua runtime errors normally stay inside `lua_pcall`. The driver also catches
SEH around callback execution and guarded memory operations. Lua panic recovery
uses a `setjmp` frame owned by the executing kernel thread; a panic on another
thread is never allowed to jump into that thread's stack.

Callback and script entry points restore their Lua stack top after execution.
This is required for nested same-thread callback dispatch.

## Lua API

The following globals are installed by `lua::expose_api`.

### Memory primitives

The `readN` and `writeN` functions are direct registered C closures, not the
`native_function` FFI path. Reads and writes are wrapped in SEH. A bad read
returns zero; a bad write is ignored.

```lua
read1(address) -> unsigned integer
read2(address) -> unsigned integer
read4(address) -> unsigned integer
read8(address) -> unsigned integer

write1(address, value)
write2(address, value)
write4(address, value)
write8(address, value)
```

The value is truncated to the selected width.

```lua
memcpy(destination, source, size) -> destination pointer
memset(destination, value, size) -> destination pointer
memcmp(left, right, size) -> numeric comparison result
```

These are raw kernel operations. They do not make arbitrary memory safe;
callers must still understand ownership, paging, IRQL, and structure layout.

### Process virtual memory

The process argument may be a PID or a raw `EPROCESS` pointer. Process memory
helpers attach to the target process internally and return Lua strings for
bulk reads.

```lua
read_process_memory(process_or_pid, address, size) -> string or nil
write_process_memory(process_or_pid, address, data) -> byte count or nil
```

The current VM context also supports selecting a process for subsequent
process-relative operations:

```lua
attach_pid(pid) -> boolean
attach_process(eprocess) -> boolean
detach() -> boolean
```

Attachments are execution-owner scoped. Calls from a different callback thread
are rejected instead of reusing another thread's `KAPC_STATE`.

### Physical memory

Single-value physical reads use `MmCopyMemory`:

```lua
readp1(physical_address) -> unsigned integer
readp2(physical_address) -> unsigned integer
readp4(physical_address) -> unsigned integer
readp8(physical_address) -> unsigned integer
```

Failure returns the implementation's failure value (`0xFFFFFFFFFFFFFFFF` for
the low-level physical read helper).

For larger or repeated accesses, map a cached section view:

```lua
local view_base, address = map_phys(physical_address, size)
-- use address for the requested range
unmap_phys(view_base)
```

`map_phys` aligns the physical base down to a page boundary and returns both
the mapped view base and the offset address. The mapped view is valid in the
current process context and must be unmapped. The section is opened lazily
through `\\Device\\PhysicalMemory`.

### Process and virtual/physical bulk helpers

```lua
readps(physical_address, size) -> native buffer pointer
readvs(virtual_address, size) -> native buffer pointer
```

These use `MmCopyMemory` and return a nonpaged buffer pointer when the entire
copy succeeds. Free returned buffers with the runtime's `free(pointer)` helper.

### CPU, MSR, control-register, and debug-register access

```lua
readmsr(msr) -> uint64
writemsr(msr, value)

readcr0() -> uint64
readcr2() -> uint64
readcr3() -> uint64
readcr4() -> uint64
readcr8() -> uint64
writecr0(value)
writecr2(value)
writecr3(value)
writecr4(value)
writecr8(value)

readdr0() -> uint64
readdr1() -> uint64
readdr2() -> uint64
readdr3() -> uint64
readdr6() -> uint64
readdr7() -> uint64
writedr0(value)
writedr1(value)
writedr2(value)
writedr3(value)
writedr6(value)
writedr7(value)
```

These operations are privileged and can destabilize or immediately crash the
machine when used with invalid values.

### Port I/O

```lua
inbyte(port) -> uint32
inword(port) -> uint32
indword(port) -> uint32
outbyte(port, value)
outword(port, value)
outdword(port, value)
```

### Timing and CPU-local state

```lua
readtsc() -> uint64
readtscpa() -> uint32
readtscp() -> uint32
readpmc(counter) -> uint64
readgsbase() -> uint64
readfsbase() -> uint64
readrsp() -> uint64
```

The `readtscpa`/`readtscp` helpers return the auxiliary processor value
captured by the corresponding instruction in the current implementation.

### Privileged instruction stubs

These are statically compiled RX stubs in the signed driver image. NtLua does
not generate executable kernel memory at runtime; this is important for HVCI
compatibility.

```lua
writecr2(value)
syscall(...)
sysretc(...)
sysretq(...)
sysenter(...)
sysexit(...)
lmsw(...)
smsw(...)
ltr(...)
str(...)
lidt(...)
lgdt(...)
lldt(...)
sidtb() -> uint64
sgdtb() -> uint64
sidtl() -> uint64
sgdtl() -> uint64
sldt() -> uint64
invd()
wbinvd()
cli()
sti()
invlpg(address)
xsetbv(index, value)
xgetbv(index) -> uint64
monitor(address)
mwait()
```

Exact calling conventions for descriptor-table and system-return stubs depend
on the machine instruction wrapper in `api.cpp`. Treat them as expert-only
interfaces and inspect the corresponding wrapper before use.

### General helpers

```lua
addressof(value) -> integer address
find_pattern(base, size, pattern, mask) -> address or nil
import(image_address) -> table of exported native functions
```

`find_pattern` searches the first matching byte pattern in `[base, base+size)`.
The mask uses `x` for an exact byte and `?` for a wildcard. The pattern is a
Lua binary string and may contain NUL bytes.

`addressof` returns the underlying pointer for strings, tables, functions,
userdata, threads, and light userdata. For numbers and booleans it returns
zero.

## Native Function Interface

`native_function` is the actual arbitrary-address FFI. It is different from
the direct C closures such as `read4`.

```lua
local fn = native_function.new(address [, return_width])
local result = fn(arg1, arg2, ...)
local address = fn:address()
local width = fn:ret_width()
fn:ret_width(1)       -- setter returns fn for chaining
```

Valid return widths are 1, 2, 4, and 8 bytes. Narrow returns are masked before
being exposed to Lua because x64 only defines the corresponding low register
bits.

The FFI supports up to 31 explicit arguments in the current implementation,
while callback handlers and fallback forwarding use a maximum of 16 captured
arguments. The target address is called directly in kernel mode; the caller
is responsible for the true prototype, IRQL requirements, pointer validity,
and lifetime.

### `nt` export table

At startup, NtLua resolves the running `ntoskrnl.exe` image and exposes a
global `nt` table. Named exports are `native_function` userdata values:

```lua
local nt_base = nt.base_address:address()
local status = nt.PsLookupProcessByProcessId(pid, out_buffer)
```

The table contains the named ntoskrnl exports found in the image export
directory. It is not a symbol/PDB database, so private unexported symbols are
not automatically available. Use pattern scanning or `MmGetSystemRoutineAddress`
through the FFI when appropriate.

## Runtime Libraries

The following libraries are embedded and executed during API exposure:

```text
KernelLuaVm/runtime/runtime.lua
KernelLuaVm/runtime/struct.lua
KernelLuaVm/runtime/gate.lua
```

### Temporary buffers: `tmp`

```lua
local buffer = tmp(size)
local address = buffer:ref()
local value = buffer:get([offset])
```

`tmp` allocates from nonpaged pool and installs a Lua `__gc` finalizer that
frees the buffer. The accessors select read/write width based on the remaining
buffer size at the requested offset: 8, then 4, then 2, then 1 bytes.

Keep the object alive while passing its pointer to a kernel routine.

### String wrappers

```lua
local ansi = ansi_string("text")
local unicode = unicode_string("text")
local pointer = ansi:ref()
```

Both return temporary objects with automatic cleanup. The wrappers allocate a
small native structure and backing buffer; they are intended for APIs such as
`MmGetSystemRoutineAddress` and trace-control structures.

### Structures: `struct.define`

```lua
local MY_STRUCT = struct.define {
    FieldA = 0x00,                       -- default 8-byte field
    FieldB = { 0x08, 4 },                -- explicit width
    Nested = { 0x10, 0x20, type = OTHER },
    Pointer = { 0x30, 8, ptr = OTHER },
}

local view = MY_STRUCT(address)
print(view.FieldA)
view.FieldB = 42
```

Field forms:

```lua
Name = offset
Name = { offset, size }
Name = { offset, size, type = NestedType }
Name = { offset, size, ptr = PointerType }
```

For sizes 1, 2, 4, and 8, the corresponding primitive is used. Other sizes
are read/written as raw byte strings. Nested and pointer fields are readable
but cannot be assigned directly.

Snapshot process memory into a structure object:

```lua
local snapshot = MY_STRUCT.read(pid_or_eprocess, address, size)
if snapshot then
    print(snapshot.FieldA)
    snapshot.FieldB = 7
    snapshot:write()
end
```

The snapshot keeps the backing Lua string, target process, and target address
so `:write()` can copy the modified buffer back.

### Admission gates: `gate.compile`

`gate.compile` turns readable Lua policy into a fixed-width instruction stream
interpreted by signed driver code. It supports:

```lua
gate.compile {
    { { arg = 0, eq = 123 } },
    { { thread = 0x80, mask = 0xFFFFFFFF, eq = 0x36 },
      { thread = 0x74, mask = 0xFF, ne = 0 } },
}
```

Conditions in one row are ANDed. Rows are ORed. Selectors are:

- `arg = 0..15`: captured callback argument
- `stack = offset`: qword at `rsp + offset`, bounded to the live kernel stack
- `thread = offset`: qword at `KTHREAD + offset`, bounded to the supported
  KTHREAD header range

Operators are `eq`, `ne`, `lt`, `gt`, `le`, `ge`, `range`, `anybits`, and
`allbits`. An optional `mask` is applied before comparison. Programs are
limited to 32 five-word instructions.

## Callback Bridge

The callback bridge precompiles 256 capture trampolines into the signed
driver image. A trampoline captures up to 16 raw arguments plus:

1. Current `KTHREAD`
2. Kernel stack base
3. Trap-time RSP

It then dispatches through the callback registry.

### Event registration

```lua
local eid = AllocateEvent()
SetHandler(eid, argc, function(arg1, ..., thread, stack_base, rsp)
    return result
end [, nonblocking])
local trampoline = GetTrampoline(eid)
```

Handlers receive `argc` captured arguments followed by the three context
values. The return value is treated as an unsigned 64-bit result and is
returned to the native caller.

```lua
FreeEvent(eid)
```

`FreeEvent` disables the slot, clears its fallback and gate, and releases its
Lua registry reference.

### Fallbacks

```lua
SetFallback(eid, native_address_or_native_function [, return_width])
SetFallbackValue(eid, value)
ClearFallback(eid)
```

Fallbacks run when the VM cannot or should not run the handler: elevated IRQL,
gate rejection, lock timeout, or a nonblocking event under contention.
Fallback addresses must be canonical kernel addresses.

### `PASS_THROUGH`

```lua
return PASS_THROUGH
```

This is a special result. The bridge releases `LL` and invokes the configured
fallback natively with the captured arguments. It is useful for interception
policies that deny a small subset in Lua but should execute the original
function directly for the allow path.

### Wait bounds and miss counters

```lua
SetWait(eid, milliseconds)
SetWait(eid)                 -- restore defaults
local misses = EventMisses(eid)
```

Gated events default to a bounded 250 ms wait. A timeout runs the fallback and
increments the cumulative event miss counter. Ungated blocking events retain
their normal blocking behavior unless explicitly configured.

### Teardown callbacks

```lua
OnTeardown(function()
    -- restore external state here
end)
```

Registered callbacks execute during RESET and driver unload while the Lua
state is still valid. Each callback is protected by the driver; one teardown
failure does not prevent later teardown callbacks from running.

Nested `pcall` is normally unnecessary inside `OnTeardown` because the driver
already invokes each callback through `lua_pcall`.

## Tracked Patches

Use tracked patches for kernel pointer/data modifications that must be undone
before reset or unload:

```lua
local patch = TrackPatch(target_address, replacement [, width])
RestorePatch(patch)
RestoreAllPatches()
local conflicts = PatchConflicts()
```

The driver records the original value and restores it only if the target still
contains the expected replacement. If another component changed the target,
NtLua refuses to overwrite that newer value and increments the conflict count.

Tracked patches are automatically restored during callback teardown. This is
the preferred mechanism for GetCpuClock, HvlGetQpcBias, callback function
pointers, and similar external hook locations.

Raw `write1`/`write8` calls remain available for research use but are not
automatically owned by the lifecycle manager.

## Shipped Scripts

### `scripts/ProcessMonitor.lua`

Registers `PsSetCreateProcessNotifyRoutine`, records process creation and exit
events, resolves image names, and exposes:

```lua
StopProcessMonitor()
```

It registers `OnTeardown` and makes cleanup idempotent. The callback is
deregistered and its event freed automatically during reset/unload.

### `scripts/KernelCallbacks.lua`

Enumerates eight callback families using pattern scanning and structure
walking:

- Process
- Thread
- ImageLoad
- Registry
- Object process
- Object thread
- Object desktop
- Driver verification

Important script APIs:

```lua
print_callbacks()
filter_callbacks(predicate)
remove_callback(entry)
restore_callback(entry)
remove_all([driver_substring])
restore_all()
hook_callback(entry, lua_handler [, argc])
```

The script detects process Ex/Ex2 callback versions from callback-block flags,
tracks removals, supports trampoline replacement, and includes a WdFilter Ex2
process-notify demonstration that denies `notepad.exe`.

It registers `OnTeardown` to unhook and restore removed callbacks.

### `scripts/InfinityHook.lua`

Implements the InfinityHookPro-style path:

1. Enables the Circular Kernel Context Logger syscall trace.
2. Locates the ETW debugger/logger data.
3. Resolves the GetCpuClock/QPC bias path.
4. Installs a tracked timestamp trampoline.
5. Uses a gate on `KTHREAD.CallIndex` and `PreviousMode` so unhooked syscall
   timestamps never enter Lua.
6. Walks entry frames to replace the per-syscall function pointer.
7. Skips expensive exit-frame walks with a bounded active-marker probe.
8. Hooks selected SSDT services through `HookSyscall(name, fn)`.

The demo hooks `NtCreateFile`, `NtOpenFile`, and `NtTraceControl`. Allow paths
return `PASS_THROUGH`, so the original syscall runs without holding the VM
lock. `UnhookAll()` restores tracked patches and callback events.

The script exposes runtime diagnostics through `worker()`, including gate
matches, walk statistics, and `EventMisses` counts. It registers `OnTeardown`
before installing its external patches.

### `scripts/EscalateToken.lua`

Provides two research helpers:

```lua
FindProcess(pid) -> EPROCESS pointer
EscalateToken(target_eprocess [, source_eprocess])
```

The helper locates the token field by comparing the target process structure
against the referenced source token, then writes the source token pointer into
the target process. This is intentionally dangerous and version-dependent.

## Safety Rules

### HVCI

NtLua does not JIT or allocate runtime executable kernel memory. Privileged
instruction stubs are statically compiled into an RX-only `.stub` section.
The Lua heap uses nonpaged NX memory. `TrackPatch` changes data/pointers, not
driver code pages.

HVCI compatibility does not make arbitrary pointer writes, physical memory
access, or arbitrary calls safe. PatchGuard, build-specific structures, and
third-party protection can still reject or detect these operations.

### IRQL

The VM requires PASSIVE-level execution for operations that may wait or touch
general kernel services. Callback dispatches above PASSIVE use fallbacks. Gate
evaluation is deliberately limited to captured registers, bounded stack reads,
and bounded KTHREAD reads so it can run in hot paths without taking `LL`.

Never call a Lua handler at an IRQL where the handler's native calls are not
valid. `readcr8()` and the callback context are available for script-side
checks, but they do not make an unsafe operation safe.

### Pointer and structure validity

Most useful structures are undocumented and version-dependent. A structure
definition that works on one Windows build may silently read or write the
wrong field on another. Prefer pattern scanning, build checks, validation,
tracked patches, and restore functions.

### Fallback correctness

If a hook handler can time out, configure a real native fallback. Returning a
constant fallback for a function that returns a handle, pointer, or structured
status can corrupt the caller even if the machine does not immediately crash.

### Teardown

The safest order is always:

```text
Restore tracked patches
Restore callback registrations
Free callback events
Stop the logger/session
Only then stop/unload NtLua
```

Use `OnTeardown` for script-owned cleanup and `TrackPatch` for pointer/data
changes that must survive script errors or RESET.

## Troubleshooting

### The console reports a Lua error with a filename

This is expected: the console sends `script-name\0source\0`, and the driver
passes the name to `luaL_loadbuffer`. Runtime errors include a Lua traceback.

### A callback is missed

Check:

```lua
EventMisses(eid)
PatchConflicts()
```

For hot callbacks, install a gate so nonmatching events never approach the VM.
Use a correct native fallback and keep the handler short.

### The system becomes slow

Do not run a heavy Lua handler on a system-hot callback such as every file open
or every timestamp. Use a gate, `PASS_THROUGH` for allow paths, bounded waits,
and the miss counter. A serialized Lua VM cannot process unlimited system-wide
events synchronously.

### RESET or unload leaves a hook behind

Use `TrackPatch` and `OnTeardown`. A raw `write8` performed by an arbitrary
script cannot be discovered automatically. Inspect `PatchConflicts()` and
restore the external owner before stopping the service.

### The process context behaves unexpectedly

`attach_pid` and `attach_process` are execution-owner scoped. Calls must occur
inside the active VM execution context; callback threads cannot reuse another
thread's `KAPC_STATE`.

## Current Non-Features

NtLua currently uses one shared Lua state serialized by `LL`.
There is no parallel Lua execution and no coroutine scheduler provided by the
driver.

The removed runtime JIT/shellcode execution path is also intentionally absent
for HVCI compatibility. Use statically compiled driver code or existing kernel
exports through `native_function`.
