#pragma once
#include "crt/crt.h"
#include <ntifs.h>
#include <intrin.h>
#include "lua/state.hpp"

// Spinlock with owner tracking (for callback reentrancy detection).
// Moved here from main.cpp so both main.cpp and callback.cpp can use it.
//
struct spinlock
{
    volatile long value = 0;
    volatile void* owner = nullptr;

    void lock()
    {
        KeEnterCriticalRegion();
        while ( _interlockedbittestandset( &value, 0 ) )
            _mm_pause();
        owner = (void*) KeGetCurrentThread();
    }
    bool try_lock()
    {
        KeEnterCriticalRegion();
        if ( _interlockedbittestandset( &value, 0 ) )
        {
            KeLeaveCriticalRegion();
            return false;
        }
        owner = (void*) KeGetCurrentThread();
        return true;
    }
    void unlock()
    {
        owner = nullptr;
        _interlockedbittestandreset( &value, 0 );
        KeLeaveCriticalRegion();
    }
    bool owned_by_current() const
    {
        return owner == (void*) KeGetCurrentThread();
    }
};
struct unique_lock
{
    spinlock& lock;
    bool acquired;
    unique_lock( spinlock& lock, bool blocking = true ) : lock( lock )
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

// Globals - defined in main.cpp, used by callback.cpp.
//
extern lua_State* L;
extern spinlock LL;

// Universal callback bridge.
//
namespace callback
{
    static constexpr int MAX_EVENTS = 256;

    // Initialize the callback subsystem (call once in DriverEntry).
    //
    void init();

    // Destroy the callback subsystem (call in unload, before lua::destroy).
    // Marks all event slots inactive so trampolines become no-ops.
    //
    void destroy();

    // Expose callback Lua API to a Lua state.
    // Adds: AllocateEvent, SetHandler, GetTrampoline, FreeEvent.
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
