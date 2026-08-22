#include "ioctl.hpp"
#include "../logger.hpp"
#include "../crt/crt.h"
#include "native_function.hpp"

// - Registry -
//
// A flat table of script-authored IOCTL handlers, keyed by the DeviceIoControl
// code. Lookups happen per-IRP in device_control; registration happens once per
// script load. The spinlock is held only around table mutation / snapshot -
// never during Lua execution (the handler may run arbitrary kernel code).
//
struct ioctl_registration
{
    vm_instance* owner    = nullptr;  // instance that owns this slot
    int          lua_ref = LUA_NOREF;  // luaL_ref in owner->L's registry
    bool         active  = false;      // slot in use
    uint32_t     code    = 0;          // DeviceIoControl code this handles
};

static ioctl_registration ioctl_registry[ ioctl::MAX_IOCTLS ];
static KSPIN_LOCK       ioctl_registry_lock;

// Reserved NTLUA_* codes: scripts cannot register these. The built-in
// branches in device_control fire first regardless, but rejecting here gives
// a clear error instead of a handler that silently never fires.
//
static bool is_reserved_code( uint32_t code )
{
    switch ( code )
    {
        case NTLUA_TAIL_TRACE: case NTLUA_TRACE_CTL: case NTLUA_TAIL_LOG:
        case NTLUA_INSTANCE_CREATE: case NTLUA_INSTANCE_DESTROY:
        case NTLUA_INSTANCE_LIST: case NTLUA_INSTANCE_RUN:
        case NTLUA_INSTANCE_RESET: case NTLUA_INSTANCE_WORKER_CTL:
            return true;
        default: return false;
    }
}

namespace ioctl
{
    void init()
    {
        // Idempotent: the lock is a static that lives for the lifetime of the
        // driver. Re-initialising it from reset_instance (via callback::init)
        // while a concurrent register/dispatch on another instance holds it
        // corrupts the lock, so initialise once at DriverEntry and never again.
        //
        static bool initialized = false;
        if ( initialized )
            return;
        KeInitializeSpinLock( &ioctl_registry_lock );
        initialized = true;
    }

    void begin_teardown()
    {
        KIRQL irql;
        KeAcquireSpinLock( &ioctl_registry_lock, &irql );
        for ( int i = 0; i < MAX_IOCTLS; i++ )
            ioctl_registry[ i ].active = false;
        KeReleaseSpinLock( &ioctl_registry_lock, irql );
    }

    void destroy( vm_instance* inst )
    {
        if ( !inst )
            return;

        lua_State* Ls = inst->L;
        int refs[ MAX_IOCTLS ];

        KIRQL irql;
        KeAcquireSpinLock( &ioctl_registry_lock, &irql );
        for ( int i = 0; i < MAX_IOCTLS; i++ )
        {
            if ( ioctl_registry[ i ].active && ioctl_registry[ i ].owner == inst )
            {
                refs[ i ] = ioctl_registry[ i ].lua_ref;
                ioctl_registry[ i ].owner = nullptr;
                ioctl_registry[ i ].lua_ref = LUA_NOREF;
                ioctl_registry[ i ].active = false;
            }
            else
            {
                refs[ i ] = LUA_NOREF;
            }
        }
        KeReleaseSpinLock( &ioctl_registry_lock, irql );

        // Release the registry references outside the spinlock: luaL_unref
        // runs Lua GC bookkeeping and must not hold a spinlock.
        //
        for ( int i = 0; i < MAX_IOCTLS; i++ )
        {
            if ( refs[ i ] != LUA_NOREF )
                luaL_unref( Ls, LUA_REGISTRYINDEX, refs[ i ] );
        }
    }

    bool register_ioctl( vm_instance* owner, uint32_t code, int lua_ref )
    {
        if ( !owner || lua_ref == LUA_NOREF )
            return false;
        if ( is_reserved_code( code ) )
            return false;

        KIRQL irql;
        KeAcquireSpinLock( &ioctl_registry_lock, &irql );

        // First-wins: an existing handler for this code from any owner blocks
        // a new one, so two scripts cannot silently share one IRP.
        //
        for ( int i = 0; i < MAX_IOCTLS; i++ )
        {
            if ( ioctl_registry[ i ].active && ioctl_registry[ i ].code == code )
            {
                KeReleaseSpinLock( &ioctl_registry_lock, irql );
                return false;
            }
        }

        // Find a free slot.
        //
        for ( int i = 0; i < MAX_IOCTLS; i++ )
        {
            if ( !ioctl_registry[ i ].active )
            {
                ioctl_registry[ i ].owner = owner;
                ioctl_registry[ i ].code = code;
                ioctl_registry[ i ].lua_ref = lua_ref;
                ioctl_registry[ i ].active = true;
                KeReleaseSpinLock( &ioctl_registry_lock, irql );
                return true;
            }
        }

        KeReleaseSpinLock( &ioctl_registry_lock, irql );
        return false;  // table full
    }

    bool unregister_ioctl( vm_instance* owner, uint32_t code )
    {
        if ( !owner )
            return false;

        KIRQL irql;
        KeAcquireSpinLock( &ioctl_registry_lock, &irql );
        bool any = false;
        for ( int i = 0; i < MAX_IOCTLS; i++ )
        {
            if ( ioctl_registry[ i ].active && ioctl_registry[ i ].owner == owner &&
                 ioctl_registry[ i ].code == code )
            {
                ioctl_registry[ i ].active = false;
                ioctl_registry[ i ].owner = nullptr;
                ioctl_registry[ i ].lua_ref = LUA_NOREF;
                any = true;
            }
        }
        KeReleaseSpinLock( &ioctl_registry_lock, irql );
        return any;
    }

    // - Lua API -
    //
    static int l_register_ioctl( lua_State* L )
    {
        vm_instance* inst = vm::lua_owner( L );
        if ( !inst || !lua_isfunction( L, 2 ) )
        {
            lua_pushunsigned( L, 0 );
            return 1;
        }

        uint32_t code = ( uint32_t ) lua_tounsigned( L, 1 );
        int ref = luaL_ref( L, LUA_REGISTRYINDEX );  // consumes arg 2
        if ( register_ioctl( inst, code, ref ) )
        {
            lua_pushunsigned( L, 1 );
            return 1;
        }

        // Registration failed: the ref is now held but unused; release it so
        // the registry does not leak a reference to a discarded handler.
        //
        luaL_unref( L, LUA_REGISTRYINDEX, ref );
        lua_pushunsigned( L, 0 );
        return 1;
    }

    static int l_unregister_ioctl( lua_State* L )
    {
        vm_instance* inst = vm::lua_owner( L );
        if ( !inst )
        {
            lua_pushunsigned( L, 0 );
            return 1;
        }
        uint32_t code = ( uint32_t ) lua_tounsigned( L, 1 );
        lua_pushunsigned( L, unregister_ioctl( inst, code ) ? 1 : 0 );
        return 1;
    }

    // - CTL_CODE -
    // Builds a Windows IOCTL code: (DeviceType << 16) | (Access << 14) |
    // (Function << 2) | Method. FUNCTION codes 0x000-0x7FF are reserved for
    // Microsoft; scripts should use 0x800+ so they never alias a standard
    // IOCTL. METHOD_BUFFERED gives the handler SystemBuffer (kernel memory,
    // always valid); METHOD_NEITHER would hand over raw user pointers that
    // only mean something attached to the calling process.
    //
    static int l_ctl_code( lua_State* L )
    {
        uint32_t device_type = ( uint32_t ) lua_tounsigned( L, 1 );
        uint32_t function    = ( uint32_t ) lua_tounsigned( L, 2 );
        uint32_t method      = ( uint32_t ) lua_tounsigned( L, 3 );
        uint32_t access      = ( uint32_t ) lua_tounsigned( L, 4 );
        lua_pushunsigned( L,
            ( uint64_t ) ( ( device_type << 16 ) | ( access << 14 ) |
                           ( function << 2 ) | method ) );
        return 1;
    }

    void expose_api( lua_State* L )
    {
        lua_pushcfunction( L, &l_register_ioctl );
        lua_setglobal( L, "register_ioctl" );
        lua_pushcfunction( L, &l_unregister_ioctl );
        lua_setglobal( L, "unregister_ioctl" );

        lua_pushcfunction( L, &l_ctl_code );
        lua_setglobal( L, "CTL_CODE" );

        lua_pushunsigned( L, 0 ); lua_setglobal( L, "METHOD_BUFFERED" );
        lua_pushunsigned( L, 1 ); lua_setglobal( L, "METHOD_IN_DIRECT" );
        lua_pushunsigned( L, 2 ); lua_setglobal( L, "METHOD_OUT_DIRECT" );
        lua_pushunsigned( L, 3 ); lua_setglobal( L, "METHOD_NEITHER" );

        lua_pushunsigned( L, 0 ); lua_setglobal( L, "FILE_ANY_ACCESS" );
        lua_pushunsigned( L, 1 ); lua_setglobal( L, "FILE_READ_ACCESS" );
        lua_pushunsigned( L, 2 ); lua_setglobal( L, "FILE_WRITE_ACCESS" );
    }

    // - Dispatch -
    //
    void dispatch( PIRP irp, PIO_STACK_LOCATION sp )
    {
        uint32_t code = ( uint32_t ) sp->Parameters.DeviceIoControl.IoControlCode;

        // Clean default: a handler that forgets to set IoStatus leaves the IRP
        // in a success/0 state instead of whatever was there before.
        //
        irp->IoStatus.Status      = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;

        // Snapshot the registration under the spinlock, then release: the
        // handler runs Lua (arbitrary kernel code) and must never hold a
        // spinlock. The owner pointer is from a fixed, never-freed pool, so
        // the snapshot is safe to use after the lock drops.
        //
        vm_instance* owner = nullptr;
        int lua_ref = LUA_NOREF;
        {
            KIRQL irql;
            KeAcquireSpinLock( &ioctl_registry_lock, &irql );
            for ( int i = 0; i < MAX_IOCTLS; i++ )
            {
                if ( ioctl_registry[ i ].active && ioctl_registry[ i ].code == code )
                {
                    owner = ioctl_registry[ i ].owner;
                    lua_ref = ioctl_registry[ i ].lua_ref;
                    break;
                }
            }
            KeReleaseSpinLock( &ioctl_registry_lock, irql );
        }

        if ( !owner || lua_ref == LUA_NOREF )
        {
            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            return;
        }

        // Acquire the instance lock (bounded) so the Lua state is stable.
        // Same reentrancy rule as the callback bridge: if this thread already
        // owns the lock (the handler was reached via an in-VM FFI call), run
        // inline instead of re-acquiring the non-reentrant mutex.
        //
        bool reentrant = owner->lock.owned_by_current();
        if ( !reentrant )
        {
            // 250ms ceiling, same as gated callbacks: a wedged handler must
            // not stall the caller's DeviceIoControl forever.
            //
            if ( !owner->lock.lock_for( 250 ) )
            {
                logger::error( "ioctl 0x%X: VM busy, handler skipped\n", code );
                irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
                return;
            }
        }

        if ( !owner->L )
        {
            if ( !reentrant ) owner->lock.unlock();
            return;
        }

        // Hand the handler the raw IRP and device object. The handler reads
        // and writes irp->IoStatus and SystemBuffer through the FFI; the driver
        // still completes the IRP after it returns, so a handler that calls
        // IoCompleteRequest double-completes it (bugcheck 0x4B).
        //
        lua_State* L = owner->L;
        PDEVICE_OBJECT device = sp->DeviceObject;

        int base = lua_gettop( L );

        __try
        {
            lua_rawgeti( L, LUA_REGISTRYINDEX, lua_ref );
            lua_pushunsigned( L, ( uint64_t ) ( uintptr_t ) irp );
            lua_pushunsigned( L, ( uint64_t ) ( uintptr_t ) device );

            int pcall_status = lua_pcall( L, 2, 0, 0 );

            if ( pcall_status != 0 )
            {
                const char* msg = lua_tolstring( L, -1, nullptr );
                logger::error( "ioctl 0x%X handler: %s\n", code, msg ? msg : "(non-string error)" );
                irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
                irp->IoStatus.Information = 0;
            }

            lua_settop( L, base );
        }
        __except ( 1 )
        {
            logger::error( "ioctl 0x%X handler SEH: %x\n", code, GetExceptionCode() );
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = 0;
            lua_settop( L, base );
        }

        if ( !reentrant ) owner->lock.unlock();
    }
}