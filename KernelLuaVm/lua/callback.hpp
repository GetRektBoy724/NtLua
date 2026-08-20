#pragma once
#include "../crt/crt.h"
#include <ntifs.h>
#include <intrin.h>
#include "state.hpp"

struct vm_instance;  // fwd decl - full type in vm.hpp, included by callback.cpp

// VM lock with owner tracking (for callback reentrancy detection).
// Moved here from main.cpp so both main.cpp and callback.cpp can use it.
// Backed by a KMUTEX so the blocking path waits at PASSIVE_LEVEL instead of
// spinning. FAST_MUTEX is deliberately NOT used: it raises IRQL to
// APC_LEVEL, but the VM runs arbitrary kernel code (via the FFI) that must
// execute at PASSIVE_LEVEL. A zero-timeout wait gives the nonblocking path.
//
struct vm_lock
{
    KMUTEX mutex = {};
    volatile void* owner = nullptr;

    void init()
    {
        KeInitializeMutex( &mutex, 0 );
    }
    void lock()
    {
        KeWaitForSingleObject( &mutex, Executive, KernelMode, FALSE, nullptr );
        owner = (void*) KeGetCurrentThread();
    }
    bool try_lock()
    {
        LARGE_INTEGER timeout = {};
        NTSTATUS status = KeWaitForSingleObject( &mutex, Executive, KernelMode, FALSE, &timeout );
        // STATUS_TIMEOUT is a success-severity code, so NT_SUCCESS would be
        // wrong here: a busy mutex expires the zero-length wait and returns
        // STATUS_TIMEOUT WITHOUT acquiring ownership. Releasing a mutex we
        // never owned raises STATUS_MUTANT_NOT_OWNED (bugcheck 0x3B).
        if ( status == STATUS_TIMEOUT )
            return false;
        owner = (void*) KeGetCurrentThread();
        return true;
    }
    bool lock_for( uint32_t ms )
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000i64 * ms;
        NTSTATUS status = KeWaitForSingleObject( &mutex, Executive, KernelMode, FALSE, &timeout );
        if ( status == STATUS_TIMEOUT )
            return false;
        owner = (void*) KeGetCurrentThread();
        return true;
    }
    void unlock()
    {
        owner = nullptr;
        KeReleaseMutex( &mutex, FALSE );
    }
    bool owned_by_current() const
    {
        return owner == (void*) KeGetCurrentThread();
    }
};
struct unique_lock
{
    vm_lock& lock;
    bool acquired;
    unique_lock( vm_lock& lock, bool blocking = true ) : lock( lock )
    {
        if ( blocking )
        {
            lock.lock();
            acquired = true;
        }
        else
            acquired = lock.try_lock();
    }
    ~unique_lock()
    {
        if ( acquired )
            lock.unlock();
    }
};

// Universal callback bridge.
//
namespace callback
{
    static constexpr int MAX_EVENTS = 256;

    // Initialize the callback subsystem (call once in DriverEntry).
    //
    void init();

    // Stop new dispatches and wait for already-running trampolines.
    //
    void begin_teardown();

    // Run registered Lua cleanup callbacks on inst; the instance's state is
    // destructible afterwards.
    //
    void run_teardown( vm_instance* inst );

    // Clear callback, teardown and patch references owned by inst.
    //
    void destroy( vm_instance* inst );

    // Expose callback Lua API to a Lua state.
    // Adds: AllocateEvent, SetHandler, GetTrampoline, FreeEvent,
    //       SetFallback, SetFallbackValue, ClearFallback, SetGate,
    //       SetWait, EventMisses, OnTeardown, TrackPatch, RestorePatch,
    //       RestoreAllPatches, PASS_THROUGH.
    //
    void expose_api( lua_State* L );

    // The dispatch function called by every capture trampoline.
    // Acquires LL, looks up the handler, calls lua_pcall, returns result.
    // thread/stack_base/rsp are trap-time values captured in the trampoline
    // (KTHREAD pointer, KPCR.Prcb.RspBase, kernel RSP) - see callback.cpp.
    //
    uint64_t dispatch( int event_id, uint64_t args[16], uint64_t thread, uint64_t stack_base, uint64_t rsp );

    // Get trampoline address for an event_id (for passing to kernel registration APIs).
    //
    void* get_trampoline( int event_id );
};
