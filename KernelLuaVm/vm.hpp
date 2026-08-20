#pragma once
#include <ntifs.h>
#include "logger.hpp"
#include "lua/callback.hpp"

// A kernel memory write tracked for restoration (was file-local in callback.cpp).
//
struct tracked_patch
{
    uint64_t target      = 0;
    uint64_t original    = 0;
    uint64_t replacement = 0;
    uint8_t  width       = 8;
    bool     active      = false;
};

// Per-instance VM state. Each instance is an independent Lua universe with
// its own lua_State, execution lock, output session, process-attach state,
// teardown callbacks and tracked patches. The 32MB session is NOT embedded:
// it is pool-allocated per instance (log_session pointer) so the driver
// image reserves no .bss.
//
struct vm_instance
{
    uint32_t id;
    bool     active;           // in-use

    lua_State* L = nullptr;
    vm_lock    lock;           // per-instance execution lock (replaces global LL)

    logger::session* log_session = nullptr;   // pool-allocated, own logs/errors

    // Process-attach state (was global in main.cpp)
    //
    PEPROCESS      attached_process = nullptr;
    KAPC_STATE     apc_state;
    volatile void* context_owner = nullptr;
    bool           context_active = false;
    bool           process_attached = false;

    // Per-instance teardown callbacks (was global in callback.cpp)
    //
    static constexpr int MAX_TEARDOWN_CALLBACKS = 32;
    int32_t teardown_refs[ MAX_TEARDOWN_CALLBACKS ];

    // Per-instance tracked patches (was global in callback.cpp)
    //
    static constexpr int MAX_TRACKED_PATCHES = 256;
    tracked_patch        patches[ MAX_TRACKED_PATCHES ];
    int64_t              patch_conflicts = 0;

    // Per-instance worker thread. Polls `worker()` from kernel-side so the
    // loop survives console restarts and avoids the user-mode round-trip
    // (no DeviceIoControl per tick). The thread blocks on stop_event; the
    // `running` flag is the user toggle for worker on/off (read at the top
    // of every poll iteration, no thread restart needed).
    //
    HANDLE worker_thread_handle = nullptr;  // from PsCreateSystemThread, retained for join
    KEVENT worker_stop_event;                // signalled to ask thread to exit
    bool   worker_running = false;           // user toggle (default: true)
    bool   worker_active  = false;           // thread has been created and not yet exited
};

// Fixed pool of VM instances, pool-allocated (pointers, no BSS).
//
namespace vm
{
    static constexpr int MAX_INSTANCES = 4;

    // The instance structs are a fixed, embedded array - never freed, so a
    // lock-free dispatch reader that has resolved an `owner` pointer can
    // never observe a freed struct. Slots are activated/deactivated via
    // alloc()/free() (which only flip `active` and re-init the lock); the
    // per-instance lua_State and log session are created/destroyed by the
    // caller under the instance lock. Unload is guarded by the global
    // callback rundown.
    //
    extern vm_instance instances[ MAX_INSTANCES ];

    // Only instance 0 exists after this; it IS the legacy "global" VM so
    // NTLUA_RUN / NTLUA_RESET keep working unchanged.
    //
    void init();

    // Destroy all active instances (Lua state + session) and reset the pool.
    //
    void shutdown();

    // Activate a free slot and re-init its lock + registries. Returns the
    // instance or nullptr if the pool is full. The Lua state is created by
    // the caller (vm::init does it for instance 0; NTLUA_INSTANCE_CREATE
    // does it).
    //
    vm_instance* alloc();

    // Deactivate a slot. The caller must have already destroyed the Lua
    // state and freed the session. The struct itself is NOT freed.
    //
    void free( vm_instance* inst );

    // Pool-allocate + zero an instance's log session (32MB of buffers).
    //
    logger::session* create_session();

    // Free an instance's log session.
    //
    void destroy_session( logger::session* session );

    // Returns the instance with the given id, or nullptr if out of range or
    // not active.
    //
    vm_instance* by_id( uint32_t id );

    // Resolve the owning instance from a lua_State (its lua_context->vm_owner).
    //
    vm_instance* lua_owner( lua_State* L );

    // Bracket one chunk of execution under the instance's lock (attach its
    // process, restore CR8/interrupts on exit).
    //
    void begin_ctx( vm_instance* inst );
    void end_ctx( vm_instance* inst );

    // - Process-attach helpers (Lua-facing) -
    // Each operates on the owning instance resolved from the caller's state.
    //
    bool attach_process( vm_instance* inst, PEPROCESS process );
    bool attach_pid( vm_instance* inst, uint64_t pid );
    bool detach( vm_instance* inst );

    // - Per-instance worker thread -
    // Creates the kernel-side polling loop. The worker runs until the
    // instance is destroyed or the driver unloads.
    //
    void start_worker( vm_instance* inst );
    void stop_worker( vm_instance* inst );
};