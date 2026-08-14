#include "callback.hpp"
#include "logger.hpp"
#include "lua/native_function.hpp"

// - Registry -
//
struct callback_registration
{
    int       lua_ref   = LUA_NOREF;   // luaL_ref, or LUA_NOREF if free
    uint8_t   arg_count = 0;           // args pushed to Lua / forwarded to fallback
    uint8_t   fallback_ret_width = 8;  // trusted result bytes for the fallback call
    bool      active    = false;       // slot in use
    bool      nonblocking = false;     // try LL instead of bailing to the fallback

    const void* fallback_address = nullptr; // native fn called when the VM can't run
    uint64_t    fallback_value   = 0;       // returned when no fallback_address is set
};

static callback_registration cb_registry[ callback::MAX_EVENTS ];
static KSPIN_LOCK             cb_registry_lock;
static void*                  cb_trampoline_table[ callback::MAX_EVENTS ];

// - Capture Trampoline Template -
//
// One template, instantiated 256 times. Each instance has a baked-in EventId
// so the trampoline knows which handler to dispatch to. The function declares
// 16 arguments - the compiler prologue reads RCX/RDX/R8/R9 (first 4 register
// args) and stack slots (args 5-16). When the kernel calls with fewer args,
// the extra slots are harmless garbage (ignored by the interpreter, which
// only reads arg_count values).
//
template<int EventId>
static __declspec(noinline) uint64_t capture_tramp(
    uint64_t a1,  uint64_t a2,  uint64_t a3,  uint64_t a4,
    uint64_t a5,  uint64_t a6,  uint64_t a7,  uint64_t a8,
    uint64_t a9,  uint64_t a10, uint64_t a11, uint64_t a12,
    uint64_t a13, uint64_t a14, uint64_t a15, uint64_t a16 )
{
    uint64_t args[ 16 ] = {
        a1, a2, a3, a4, a5, a6, a7, a8,
        a9, a10, a11, a12, a13, a14, a15, a16
    };
    // Snapshot trap-time context BEFORE dispatch takes the lock. gs is
    // per-CPU and can change under us at PASSIVE_LEVEL (thread migration),
    // but at trap time the current thread is by definition on the current
    // CPU, so gs reads here always describe this thread: KTHREAD (gs:0x188)
    // and the kernel stack base (KPCR.Prcb.RspBase, gs:0x1A8 - the
    // InfinityHook walk boundary). All three are safe to consume later.
    //
    uint64_t thread     = __readgsqword( 0x188 );
    uint64_t stack_base = __readgsqword( 0x1A8 );
    uint64_t rsp        = ( uint64_t ) _AddressOfReturnAddress();
    return callback::dispatch( EventId, args, thread, stack_base, rsp );
}

// Explicit instantiations - generates 256 function bodies in .text.
//
#define TRAMP( N ) \
    template uint64_t capture_tramp<N>( \
        uint64_t, uint64_t, uint64_t, uint64_t, \
        uint64_t, uint64_t, uint64_t, uint64_t, \
        uint64_t, uint64_t, uint64_t, uint64_t, \
        uint64_t, uint64_t, uint64_t, uint64_t );
#include "trampolines.inc"
#undef TRAMP

// - Fallback invocation -
// When the VM cannot run (elevated IRQL, reentrancy, or lock contention) the
// bridge routes to a user-supplied native fallback instead of returning a
// hardcoded 0. The fallback is called with exactly arg_count captured
// arguments (the same ones the kernel passed to the original routine); if no
// fallback address is set, a constant fallback_value is returned instead.
//
static uint64_t invoke_fallback(
    const void* address,
    uint8_t ret_width,
    int arg_count,
    uint64_t fallback_value,
    const uint64_t* args )
{
    if ( !address )
        return fallback_value;

    auto call = [ & ] <typename... T>(
        auto&& self, size_t index, T... values ) -> uint64_t
    {
        if constexpr ( sizeof...( T ) <= 16 )
        {
            if ( index == ( size_t ) arg_count )
                return ( ( uint64_t( __stdcall* )( T... ) ) address )( values... );
            return self( self, index + 1, values..., args[ index ] );
        }
        __assume( 0 );
    };

    uint64_t result = call( call, 0 );

    switch ( ret_width )
    {
        case 1:  result &= 0xFF; break;
        case 2:  result &= 0xFFFF; break;
        case 4:  result &= 0xFFFFFFFF; break;
        default: break;
    }

    return result;
}

// - Dispatch -
//
namespace callback
{
    uint64_t dispatch( int event_id, uint64_t args[16], uint64_t thread, uint64_t stack_base, uint64_t rsp )
    {
        // Bounds check.
        //
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return 0;

        // Snapshot the fallback fields up front so the early-return paths can
        // route to them without taking cb_registry_lock. Aligned 8-byte reads
        // are atomic on x64; a concurrent SetFallback may briefly pair a new
        // address with the previous width (benign - width is almost always 8).
        //
        const callback_registration& reg = cb_registry[ event_id ];
        const void* fb_addr  = reg.fallback_address;
        uint8_t     fb_width = reg.fallback_ret_width;
        uint64_t    fb_value = reg.fallback_value;
        int         fb_argc  = reg.arg_count;

        // Above PASSIVE_LEVEL (ETW timestamps fire at DISPATCH in DPC/interrupt
        // context) we must never wait on the VM lock: spinning there starves
        // the passive-level holder of its CPU (the original machine freeze).
        //
        if ( KeGetCurrentIrql() > PASSIVE_LEVEL )
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );

        // Reentrancy: if the current thread already holds LL (either from
        // the REPL path or a higher callback), bypass to avoid deadlock.
        // The VM lock is non-reentrant - can't re-acquire on the same thread.
        //
        if ( LL.owned_by_current() )
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );

        // Acquire LL - protects L (shared with the REPL/IOCTL path).
        // Non-blocking events try once and bail instead of spinning: they
        // fire on hot paths (e.g. ETW timestamp per syscall) where piling
        // up behind a busy lock hangs the machine.
        //
        unique_lock _g{ LL, !cb_registry[ event_id ].nonblocking };
        if ( !_g.acquired )
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );

        // Re-check active inside the lock - ensures we don't access L
        // after unload_driver has destroyed it (unload holds LL while
        // calling lua::destroy).
        //
        if ( !cb_registry[ event_id ].active ||
             cb_registry[ event_id ].lua_ref == LUA_NOREF )
            return 0;

        uint64_t result = 0;

        __try
        {
            // Push the Lua handler function from the registry.
            //
            lua_rawgeti( L, LUA_REGISTRYINDEX, cb_registry[ event_id ].lua_ref );

            // Push only arg_count arguments (the rest are garbage).
            //
            int nargs = cb_registry[ event_id ].arg_count;
            for ( int i = 0; i < nargs; i++ )
                lua_pushunsigned( L, args[ i ] );

            // Trap-time context captured in the trampoline, before the
            // lock: KTHREAD, kernel stack base (KPCR.Prcb.RspBase, gs:0x1A8)
            // and the trap RSP.
            //
            lua_pushunsigned( L, thread );
            lua_pushunsigned( L, stack_base );
            lua_pushunsigned( L, rsp );

            // Call Lua with arg_count args plus the three context values
            // (handlers that don't declare them simply drop the extras).
            // On error: log and return 0 (allow). On success: read the
            // return value (0=allow, NTSTATUS=deny/modify).
            //
            if ( lua_pcall( L, nargs + 3, 1, 0 ) )
            {
                logger::error( "callback %d: %s\n", event_id, lua_tostring( L, -1 ) );
                lua_settop( L, 0 );
            }
            else
            {
                result = lua_tounsigned( L, -1 );
                lua_settop( L, 0 );
            }
        }
        __except ( 1 )
        {
            logger::error( "callback %d SEH: %x\n", event_id, GetExceptionCode() );
            lua_settop( L, 0 );
        }

        return result;
    }

    // - Lifecycle -
    //

    void init()
    {
        KeInitializeSpinLock( &cb_registry_lock );

        for ( int i = 0; i < MAX_EVENTS; i++ )
        {
            cb_registry[ i ].lua_ref            = LUA_NOREF;
            cb_registry[ i ].arg_count          = 0;
            cb_registry[ i ].active             = false;
            cb_registry[ i ].fallback_address   = nullptr;
            cb_registry[ i ].fallback_ret_width = 8;
            cb_registry[ i ].fallback_value     = 0;
            cb_trampoline_table[ i ]            = nullptr;
        }

        // Populate trampoline table with the 256 pre-compiled addresses.
        //
        #define TRAMP( N ) cb_trampoline_table[N] = (void*) &capture_tramp<N>;
        #include "trampolines.inc"
        #undef TRAMP
    }

    void destroy()
    {
        // Mark all slots inactive. Trampolines become no-ops (dispatch checks
        // active inside LL, which unload_driver holds before lua::destroy).
        // lua_close(L) will free all registry refs automatically. Fallbacks
        // are cleared too so a straggler trampoline can't invoke a stale
        // native pointer during unload.
        //
        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        for ( int i = 0; i < MAX_EVENTS; i++ )
        {
            cb_registry[ i ].active             = false;
            cb_registry[ i ].fallback_address   = nullptr;
            cb_registry[ i ].fallback_ret_width = 8;
            cb_registry[ i ].fallback_value     = 0;
        }
        KeReleaseSpinLock( &cb_registry_lock, old );
    }

    void* get_trampoline( int event_id )
    {
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return nullptr;
        return cb_trampoline_table[ event_id ];
    }

    // - Lua API -
    //
    //  AllocateEvent()                    -> event_id (integer 0-255) or nil
    //  SetHandler(eid, argc, fn [, nonblocking])
    //  GetTrampoline(eid)                 -> address (integer) or nil
    //  FreeEvent(eid)
    //  SetFallback(eid, addr_or_fn [, ret_width])
    //  SetFallbackValue(eid, value)
    //  ClearFallback(eid)
    //

    static int allocate_event( lua_State* Ls )
    {
        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        int found = -1;
        for ( int i = 0; i < MAX_EVENTS; i++ )
        {
            if ( !cb_registry[ i ].active )
            {
                found = i;
                cb_registry[ i ].active = true;
                break;
            }
        }
        KeReleaseSpinLock( &cb_registry_lock, old );

        if ( found >= 0 )
            lua_pushunsigned( Ls, found );
        else
            lua_pushnil( Ls );
        return 1;
    }

    static int set_handler( lua_State* Ls )
    {
        int event_id  = (int) luaL_checkunsigned( Ls, 1 );
        int arg_count = (int) luaL_checkunsigned( Ls, 2 );

        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );

        // Push the Lua function (arg 3) and ref it in the registry.
        // Done at PASSIVE_LEVEL (called from REPL via IOCTL, LL is held).
        //
        lua_pushvalue( Ls, 3 );
        int new_ref = luaL_ref( Ls, LUA_REGISTRYINDEX );

        // Atomically swap the ref, arg_count and flags under the registry
        // spinlock.
        //
        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        int old_ref = cb_registry[ event_id ].lua_ref;
        cb_registry[ event_id ].lua_ref   = new_ref;
        cb_registry[ event_id ].arg_count = (uint8_t) arg_count;
        cb_registry[ event_id ].nonblocking = lua_toboolean( Ls, 4 ) != 0;
        KeReleaseSpinLock( &cb_registry_lock, old );

        // Unref the old handler (at PASSIVE, outside the spinlock).
        //
        if ( old_ref != LUA_NOREF )
            luaL_unref( Ls, LUA_REGISTRYINDEX, old_ref );

        return 0;
    }

    static int get_trampoline_addr( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        void* tramp = callback::get_trampoline( event_id );
        if ( tramp )
            lua_pushunsigned( Ls, (uint64_t) tramp );
        else
            lua_pushnil( Ls );
        return 1;
    }

    static int free_event( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return 0;

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        int ref = cb_registry[ event_id ].lua_ref;
        cb_registry[ event_id ].lua_ref = LUA_NOREF;
        cb_registry[ event_id ].active  = false;
        cb_registry[ event_id ].fallback_address = nullptr;
        cb_registry[ event_id ].fallback_ret_width = 8;
        cb_registry[ event_id ].fallback_value = 0;
        KeReleaseSpinLock( &cb_registry_lock, old );

        // Unref at PASSIVE (outside spinlock).
        //
        if ( ref != LUA_NOREF )
            luaL_unref( Ls, LUA_REGISTRYINDEX, ref );

        return 0;
    }

    // SetFallback(eid, addr_or_function [, ret_width])
    //   addr_or_function: raw integer address OR a native_function userdata
    //   (in which case its address and ret_width are copied over).
    //
    static int set_fallback( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );

        const void* address = nullptr;
        uint8_t width = 8;

        native_function* fn = ( native_function* ) luaL_testudata( Ls, 2, native_function::export_name );
        if ( fn )
        {
            address = fn->address;
            width   = fn->ret_width;
        }
        else
        {
            address = ( const void* ) lua_tounsigned( Ls, 2 );
        }

        if ( !lua_isnoneornil( Ls, 3 ) )
        {
            int w = (int) luaL_checkunsigned( Ls, 3 );
            if ( w != 1 && w != 2 && w != 4 && w != 8 )
                return luaL_error( Ls, "ret_width must be 1, 2, 4 or 8, got %d", w );
            width = (uint8_t) w;
        }

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        cb_registry[ event_id ].fallback_address = address;
        cb_registry[ event_id ].fallback_ret_width = width;
        KeReleaseSpinLock( &cb_registry_lock, old );

        return 0;
    }

    static int set_fallback_value( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );

        uint64_t value = lua_tounsigned( Ls, 2 );

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        cb_registry[ event_id ].fallback_value = value;
        KeReleaseSpinLock( &cb_registry_lock, old );

        return 0;
    }

    static int clear_fallback( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        cb_registry[ event_id ].fallback_address = nullptr;
        cb_registry[ event_id ].fallback_ret_width = 8;
        cb_registry[ event_id ].fallback_value = 0;
        KeReleaseSpinLock( &cb_registry_lock, old );

        return 0;
    }

    void expose_api( lua_State* Ls )
    {
        lua_pushcfunction( Ls, &allocate_event );
        lua_setglobal( Ls, "AllocateEvent" );

        lua_pushcfunction( Ls, &set_handler );
        lua_setglobal( Ls, "SetHandler" );

        lua_pushcfunction( Ls, &get_trampoline_addr );
        lua_setglobal( Ls, "GetTrampoline" );

        lua_pushcfunction( Ls, &free_event );
        lua_setglobal( Ls, "FreeEvent" );

        lua_pushcfunction( Ls, &set_fallback );
        lua_setglobal( Ls, "SetFallback" );

        lua_pushcfunction( Ls, &set_fallback_value );
        lua_setglobal( Ls, "SetFallbackValue" );

        lua_pushcfunction( Ls, &clear_fallback );
        lua_setglobal( Ls, "ClearFallback" );
    }
}
