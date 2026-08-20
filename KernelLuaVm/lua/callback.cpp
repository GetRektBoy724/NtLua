#include "callback.hpp"
#include "../logger.hpp"
#include "../trace_ring.hpp"
#include "native_function.hpp"

// - Admission gate ISA -
// Events may carry a compiled predicate program (policy-as-data, authored in
// Lua via gate.lua -> SetGate). The interpreter below is the only code that
// runs per-event in the hot path; it executes at any IRQL, touches no locks
// and reads only the captured args plus the always-resident kernel stack
// [rsp, stack_base). This is what lets a GetCpuClock-rate hook keep full
// synchronous semantics: no-match falls back without ever approaching the
// VM, a match blocks for LL and runs the Lua handler in-context.
//
// Instruction = 5 x uint64: { op, selector, mask, value, value2 }.
// selector = (unit << 32) | index: unit 0 -> args[index] (0..15),
// unit 1 -> *(uint64*)(rsp + index), index = byte offset (<= 0xFFF,
// bounds-checked against stack_base at evaluation time),
// unit 2 -> *(uint64*)(thread + index), the KTHREAD captured at trap time
// (index <= 0x500, inside the always-resident KTHREAD header).
// Conditions within a row AND; rows OR; OP_OR terminates a row, the program
// ends with OP_STOP.
//
static constexpr int MAX_GATE_INSTRS = 32;

enum : uint64_t
{
    OP_STOP = 0, OP_OR, OP_EQ, OP_NE, OP_LT, OP_GT, OP_LE, OP_GE,
    OP_RANGE, OP_ANYBITS, OP_ALLBITS
};

// Sentinel a handler may return to decline deciding: dispatch then invokes
// the event's configured fallback natively, with LL released. This keeps
// long-running originals (e.g. real file I/O behind an allowed syscall hook)
// from serializing the entire VM behind one mutex. If no fallback is set the
// fallback_value applies, so a sentinel can never dereference garbage.
//
static constexpr uint64_t PASS_THROUGH_SENTINEL = 0x4E744C7561504153; // "NtLuaPAS"

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

    // Bounded blocking: 0 = default (gated events 250ms, plain blocking
    // events INFINITE), else the max ms a dispatch may wait for LL. A timed
    // out dispatch runs the fallback and bumps lock_misses - degradation is
    // observable instead of convoying the machine (unbounded waits on
    // syscall-rate paths froze the whole system).
    //
    uint32_t        wait_ms     = 0;
    volatile LONG64 lock_misses = 0;

    // Gate program. Single writer (SetGate under cb_registry_lock), many
    // lock-free readers in dispatch: seqlock protocol. gate_seq odd = update
    // in progress; a reader whose seq changed across evaluation treats the
    // program as torn -> no-match (event falls back during reconfiguration).
    //
    volatile LONG   gate_len  = 0;
    volatile LONG64 gate_seq  = 0;
    uint64_t        gate_instrs[ MAX_GATE_INSTRS * 5 ] = {};
};

static callback_registration cb_registry[ callback::MAX_EVENTS ];
static KSPIN_LOCK             cb_registry_lock;
static void*                  cb_trampoline_table[ callback::MAX_EVENTS ];
static EX_RUNDOWN_REF         callback_rundown;
static bool                   callback_rundown_initialized = false;

static constexpr int MAX_TEARDOWN_CALLBACKS = 32;
static int teardown_refs[ MAX_TEARDOWN_CALLBACKS ];
static volatile bool accepting_teardown = false;

struct tracked_patch
{
    uint64_t target      = 0;
    uint64_t original    = 0;
    uint64_t replacement = 0;
    uint8_t  width       = 8;
    bool     active      = false;
};

static constexpr int MAX_TRACKED_PATCHES = 256;
static tracked_patch tracked_patches[ MAX_TRACKED_PATCHES ];
static LONG64 patch_conflicts = 0;

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
#include "../trampolines.inc"
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

// - Gate evaluation -
// Lock-free seqlock reader over the event's program. Returns true (match)
// only for a consistent read whose predicate admitted the event; a torn
// read (concurrent SetGate) returns false so the event takes the fallback
// for the duration of the reconfiguration.
//
static uint64_t gate_load( uint64_t selector, const uint64_t args[ 16 ], uint64_t thread, uint64_t rsp, uint64_t stack_base, bool& ok )
{
    uint64_t unit  = selector >> 32;
    uint64_t index = selector & 0xFFFFFFFF;

    if ( unit == 0 && index < 16 )
        return args[ index ];

    // Stack reads are confined to [rsp, stack_base) - the live kernel stack
    // of the thread that trapped, always resident, safe at any IRQL.
    //
    if ( unit == 1 && index <= 0xFFF && rsp + index + 8 <= stack_base )
        return *( volatile uint64_t* ) ( rsp + index );

    // Thread reads hit the KTHREAD of the trapped thread (nonpaged, valid
    // for the whole dispatch - the thread cannot exit mid-syscall).
    //
    if ( unit == 2 && index <= 0x500 )
        return *( volatile uint64_t* ) ( thread + index );

    ok = false;
    return 0;
}

static bool gate_eval( int event_id, const uint64_t args[ 16 ], uint64_t thread, uint64_t rsp, uint64_t stack_base )
{
    callback_registration& reg = cb_registry[ event_id ];

    LONG64 seq = reg.gate_seq;
    MemoryBarrier();
    if ( seq & 1 )
        return false;

    LONG count = reg.gate_len;
    bool result = false, row = true, done = false;

    for ( LONG i = 0; i < count && !done; i++ )
    {
        const uint64_t* c = &reg.gate_instrs[ i * 5 ];

        if ( c[ 0 ] == OP_OR )
        {
            if ( row ) { result = true; done = true; }
            else row = true;
            continue;
        }
        if ( c[ 0 ] == OP_STOP )
        {
            if ( row ) result = true;
            done = true;
            continue;
        }
        // Row already failed: scan forward to the next marker only.
        //
        if ( !row )
            continue;

        bool ok = true;
        uint64_t v = gate_load( c[ 1 ], args, thread, rsp, stack_base, ok ) & c[ 2 ];
        if ( !ok )
        {
            row = false;
            continue;
        }

        const uint64_t& a = c[ 3 ];
        const uint64_t& b = c[ 4 ];
        switch ( c[ 0 ] )
        {
            case OP_EQ:      if ( v != a )        row = false; break;
            case OP_NE:      if ( v == a )        row = false; break;
            case OP_LT:      if ( v >= a )        row = false; break;
            case OP_GT:      if ( v <= a )        row = false; break;
            case OP_LE:      if ( v >  a )        row = false; break;
            case OP_GE:      if ( v <  a )        row = false; break;
            case OP_RANGE:   if ( v < a || v > b ) row = false; break;
            case OP_ANYBITS: if ( ( v & a ) == 0 ) row = false; break;
            case OP_ALLBITS: if ( ( v & a ) != a ) row = false; break;
            default:         row = false; break;
        }
    }

    MemoryBarrier();
    if ( reg.gate_seq != seq )
        return false;
    return result;
}

// - Handler execution -
// Runs the Lua handler for event_id. Must be called with LL held by the
// current thread (either from dispatch's lock or the nested re-entrant
// path below). The stack top is saved and restored around the call: a
// re-entrant invocation runs while an outer execute()/pcall frame sits
// on the same state, and restoring the top (instead of clearing to 0)
// keeps that outer frame's values intact.
//
static uint64_t run_handler( int event_id, const uint64_t args[16], uint64_t thread, uint64_t stack_base, uint64_t rsp )
{
    // Re-check active - ensures we don't access L after unload_driver has
    // destroyed it (unload holds LL while calling lua::destroy).
    //
    if ( !cb_registry[ event_id ].active ||
         cb_registry[ event_id ].lua_ref == LUA_NOREF )
        return 0;

    // Fresh instruction budget for this handler (see lua_context).
    //
    lua::get_context( L )->budget_remaining = lua::lua_context::EXECUTION_BUDGET;

    int base = lua_gettop( L );
    uint64_t result = 0;

    // Trace handler execution when enabled: name + captured args up front,
    // RETURN with the result on success, TRAP on Lua error or SEH (which
    // route to the fallback below via PASS_THROUGH_SENTINEL).
    //
    char     event_name[ 16 ] = {};
    uint64_t targv[ 4 ] = {};
    uint32_t targc = 0;
    bool     tracing = trace::enabled();
    if ( tracing )
    {
        sprintf_s( event_name, sizeof( event_name ), "cb %d", event_id );
        targc = cb_registry[ event_id ].arg_count;
        if ( targc > 4 ) targc = 4;
        for ( uint32_t i = 0; i < targc; i++ )
            targv[ i ] = args[ i ];
    }

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

        if ( tracing )
            trace::push( NTLUA_TRK_CALL, event_name, targc, targv, 0 );

        // Call Lua with arg_count args plus the three context values
        // (handlers that don't declare them simply drop the extras).
        // On error or SEH: route to the configured native fallback so the
        // system behaves as if the hook had not fired (without a fallback,
        // invoke_fallback returns fallback_value, i.e. 0). On success: read
        // the return value (0=allow, NTSTATUS=deny/modify).
        //
        if ( lua_pcall( L, nargs + 3, 1, 0 ) )
        {
            const char* msg = lua_tostring( L, -1 );
            if ( tracing )
                trace::push( NTLUA_TRK_TRAP, msg ? msg : "callback error", 0, nullptr, 0 );
            logger::error( "callback %d: %s\n", event_id, msg ? msg : "(non-string error object)" );
            lua_settop( L, base );
            // A broken handler must not silently read as "allow" (0) on hooks
            // where zero is meaningful. Route to the configured native
            // fallback so the system behaves as if the hook had not fired;
            // without a fallback, invoke_fallback returns fallback_value,
            // preserving the previous behavior.
            //
            result = PASS_THROUGH_SENTINEL;
        }
        else
        {
            result = lua_tounsigned( L, -1 );
            lua_settop( L, base );
            if ( tracing )
                trace::push( NTLUA_TRK_RETURN, event_name, 0, nullptr, result );
        }
    }
    __except ( 1 )
    {
        uint64_t a[ 1 ] = { ( uint64_t ) GetExceptionCode() };
        if ( tracing )
            trace::push( NTLUA_TRK_TRAP, "SEH", 1, a, 0 );
        logger::error( "callback %d SEH: %x\n", event_id, GetExceptionCode() );
        lua_settop( L, base );
        result = PASS_THROUGH_SENTINEL;
    }

    return result;
}

// - Dispatch -
//
namespace callback
{
    static uint64_t dispatch_active( int event_id, uint64_t args[16], uint64_t thread, uint64_t stack_base, uint64_t rsp )
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

        // Admission gate: evaluated before anything else, at any IRQL, with
        // no locks. A rejected event never approaches the VM, so an
        // ungated-hot event (e.g. GetCpuClock on every syscall) costs a few
        // nanoseconds in the common case instead of contending for LL.
        //
        const LONG gate_len = reg.gate_len;
        if ( gate_len && !gate_eval( event_id, args, thread, rsp, stack_base ) )
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );

        // Above PASSIVE_LEVEL (ETW timestamps fire at DISPATCH in DPC/interrupt
        // context) we must never wait on the VM lock: spinning there starves
        // the passive-level holder of its CPU (the original machine freeze).
        //
        if ( KeGetCurrentIrql() > PASSIVE_LEVEL )
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );

        // Same-thread re-entry: a Lua script (REPL or another handler) called
        // into the kernel via the FFI and triggered a hooked callback on this
        // very thread. LL is already held, so mutual exclusion against other
        // threads is guaranteed; re-acquiring the non-reentrant mutex would
        // deadlock, and dropping the event to the fallback would miss it.
        // Nested lua_pcall on the same state from the same thread is legal -
        // the interpreter re-enters itself the same way for metamethods - and
        // run_handler restores the stack top, so the in-flight frames above
        // us are untouched. Run the handler inline.
        //
        if ( LL.owned_by_current() )
        {
            uint64_t result = run_handler( event_id, args, thread, stack_base, rsp );
            // Same conversion as the main path below: a handler asking to
            // pass through must reach the native fallback, not leak the
            // sentinel value to the kernel caller.
            //
            if ( result == PASS_THROUGH_SENTINEL )
                return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );
            return result;
        }

        // A gate match waits for LL (never misses merely because the VM is
        // busy) but never unbounded: matches on syscall-rate hooks can
        // otherwise queue faster than the serialized VM drains them and
        // convoy the machine. Gated events default to a 250ms ceiling;
        // SetWait overrides per event (0 = restore defaults). A timeout
        // degrades to the fallback and counts in lock_misses.
        //
        bool acquired;
        if ( gate_len != 0 || !cb_registry[ event_id ].nonblocking )
        {
            uint32_t wait = cb_registry[ event_id ].wait_ms;
            if ( gate_len != 0 && wait == 0 )
                wait = 250;
            acquired = ( wait == 0 ) ? ( LL.lock(), true ) : LL.lock_for( wait );
        }
        else
        {
            acquired = LL.try_lock();
        }

        if ( !acquired )
        {
            InterlockedIncrement64( &cb_registry[ event_id ].lock_misses );
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );
        }

        uint64_t result = run_handler( event_id, args, thread, stack_base, rsp );
        LL.unlock();

        if ( result == PASS_THROUGH_SENTINEL )
            return invoke_fallback( fb_addr, fb_width, fb_argc, fb_value, args );

        return result;
    }

    uint64_t dispatch( int event_id, uint64_t args[16], uint64_t thread, uint64_t stack_base, uint64_t rsp )
    {
        if ( event_id < 0 || event_id >= MAX_EVENTS ||
             !ExAcquireRundownProtection( &callback_rundown ) )
            return 0;

        uint64_t result = 0;
        __try
        {
            result = dispatch_active( event_id, args, thread, stack_base, rsp );
        }
        __except ( 1 )
        {
            logger::error( "callback %d dispatch SEH: %x\n", event_id, GetExceptionCode() );
        }
        ExReleaseRundownProtection( &callback_rundown );
        return result;
    }

    static bool patch_read( uint64_t address, uint8_t width, uint64_t& value )
    {
        value = 0;
        __try
        {
            switch ( width )
            {
                case 1: value = *( volatile uint8_t* ) address; break;
                case 2: value = *( volatile uint16_t* ) address; break;
                case 4: value = *( volatile uint32_t* ) address; break;
                case 8: value = *( volatile uint64_t* ) address; break;
                default: return false;
            }
        }
        __except ( 1 )
        {
            return false;
        }
        return true;
    }

    static bool patch_write( uint64_t address, uint8_t width, uint64_t value )
    {
        __try
        {
            switch ( width )
            {
                case 1: *( volatile uint8_t* ) address = ( uint8_t ) value; break;
                case 2: *( volatile uint16_t* ) address = ( uint16_t ) value; break;
                case 4: *( volatile uint32_t* ) address = ( uint32_t ) value; break;
                case 8: *( volatile uint64_t* ) address = value; break;
                default: return false;
            }
        }
        __except ( 1 )
        {
            return false;
        }
        return true;
    }

    static bool restore_all_patches()
    {
        bool success = true;
        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        for ( int i = 0; i < MAX_TRACKED_PATCHES; i++ )
        {
            tracked_patch& patch = tracked_patches[ i ];
            if ( !patch.active )
                continue;

            uint64_t current = 0;
            if ( !patch_read( patch.target, patch.width, current ) )
            {
                success = false;
                continue;
            }

            if ( current == patch.replacement )
            {
                if ( !patch_write( patch.target, patch.width, patch.original ) )
                    success = false;
            }
            else
            {
                InterlockedIncrement64( &patch_conflicts );
            }
            patch.active = false;
        }
        KeReleaseSpinLock( &cb_registry_lock, old );
        return success;
    }

    // - Lifecycle -
    //

    void init()
    {
        KeInitializeSpinLock( &cb_registry_lock );
        if ( callback_rundown_initialized )
            ExReInitializeRundownProtection( &callback_rundown );
        else
        {
            ExInitializeRundownProtection( &callback_rundown );
            callback_rundown_initialized = true;
        }
        accepting_teardown = true;

        for ( int i = 0; i < MAX_TEARDOWN_CALLBACKS; i++ )
            teardown_refs[ i ] = LUA_NOREF;
        patch_conflicts = 0;
        for ( int i = 0; i < MAX_TRACKED_PATCHES; i++ )
            tracked_patches[ i ] = {};

        for ( int i = 0; i < MAX_EVENTS; i++ )
        {
            cb_registry[ i ].lua_ref            = LUA_NOREF;
            cb_registry[ i ].arg_count          = 0;
            cb_registry[ i ].active             = false;
            cb_registry[ i ].nonblocking        = false;
            cb_registry[ i ].fallback_address   = nullptr;
            cb_registry[ i ].fallback_ret_width = 8;
            cb_registry[ i ].fallback_value     = 0;
            cb_registry[ i ].wait_ms            = 0;
            cb_registry[ i ].lock_misses        = 0;
            cb_registry[ i ].gate_len           = 0;
            cb_registry[ i ].gate_seq           = 0;
            cb_trampoline_table[ i ]            = nullptr;
        }

        // Populate trampoline table with the 256 pre-compiled addresses.
        //
        #define TRAMP( N ) cb_trampoline_table[N] = (void*) &capture_tramp<N>;
        #include "../trampolines.inc"
        #undef TRAMP
    }

    void begin_teardown()
    {
        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        accepting_teardown = false;
        for ( int i = 0; i < MAX_EVENTS; i++ )
        {
            cb_registry[ i ].active             = false;
            cb_registry[ i ].fallback_address   = nullptr;
            cb_registry[ i ].fallback_ret_width = 8;
            cb_registry[ i ].fallback_value     = 0;
            InterlockedIncrement64( &cb_registry[ i ].gate_seq );
            cb_registry[ i ].gate_len           = 0;
            InterlockedIncrement64( &cb_registry[ i ].gate_seq );
        }
        KeReleaseSpinLock( &cb_registry_lock, old );

        ExRundownCompleted( &callback_rundown );
        ExWaitForRundownProtectionRelease( &callback_rundown );
    }

    void run_teardown( lua_State* Ls )
    {
        int base = lua_gettop( Ls );
        for ( int i = 0; i < MAX_TEARDOWN_CALLBACKS; i++ )
        {
            if ( teardown_refs[ i ] == LUA_NOREF )
                continue;

            lua_rawgeti( Ls, LUA_REGISTRYINDEX, teardown_refs[ i ] );
            if ( lua_pcall( Ls, 0, 0, 0 ) )
            {
                const char* message = lua_tostring( Ls, -1 );
                logger::error( "teardown %d: %s\n", i, message ? message : "(non-string error object)" );
            }
            lua_settop( Ls, base );
        }
    }

    void destroy( lua_State* Ls )
    {
        int refs[ callback::MAX_EVENTS ];
        int cleanup_refs[ MAX_TEARDOWN_CALLBACKS ];

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        for ( int i = 0; i < MAX_EVENTS; i++ )
        {
            refs[ i ] = cb_registry[ i ].lua_ref;
            cb_registry[ i ].lua_ref            = LUA_NOREF;
            cb_registry[ i ].active             = false;
            cb_registry[ i ].arg_count          = 0;
            cb_registry[ i ].nonblocking        = false;
            cb_registry[ i ].fallback_address   = nullptr;
            cb_registry[ i ].fallback_ret_width = 8;
            cb_registry[ i ].fallback_value     = 0;
            cb_registry[ i ].wait_ms            = 0;
            cb_registry[ i ].lock_misses        = 0;
            cb_registry[ i ].gate_len           = 0;
        }
        for ( int i = 0; i < MAX_TEARDOWN_CALLBACKS; i++ )
        {
            cleanup_refs[ i ] = teardown_refs[ i ];
            teardown_refs[ i ] = LUA_NOREF;
        }
        KeReleaseSpinLock( &cb_registry_lock, old );

        for ( int i = 0; i < callback::MAX_EVENTS; i++ )
        {
            if ( refs[ i ] != LUA_NOREF )
                luaL_unref( Ls, LUA_REGISTRYINDEX, refs[ i ] );
        }
        for ( int i = 0; i < MAX_TEARDOWN_CALLBACKS; i++ )
        {
            if ( cleanup_refs[ i ] != LUA_NOREF )
                luaL_unref( Ls, LUA_REGISTRYINDEX, cleanup_refs[ i ] );
        }

        if ( !restore_all_patches() )
            logger::error( "tracked patch restoration fault\n" );
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
        uint64_t arg_count_value = luaL_checkunsigned( Ls, 2 );
        int arg_count = ( int ) arg_count_value;

        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );
        if ( arg_count_value > 16 )
            return luaL_error( Ls, "arg_count must be between 0 and 16" );

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
        cb_registry[ event_id ].wait_ms = 0;
        cb_registry[ event_id ].lock_misses = 0;
        InterlockedIncrement64( &cb_registry[ event_id ].gate_seq );
        cb_registry[ event_id ].gate_len = 0;
        InterlockedIncrement64( &cb_registry[ event_id ].gate_seq );
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

        if ( address && ( uint64_t ) address < 0xFFFF800000000000ull )
            return luaL_error( Ls, "fallback address is not a canonical kernel address" );

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

    static int on_teardown( lua_State* Ls )
    {
        luaL_checktype( Ls, 1, LUA_TFUNCTION );
        lua_pushvalue( Ls, 1 );
        int ref = luaL_ref( Ls, LUA_REGISTRYINDEX );
        int slot = -1;

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        if ( accepting_teardown )
        {
            for ( int i = 0; i < MAX_TEARDOWN_CALLBACKS; i++ )
            {
                if ( teardown_refs[ i ] == LUA_NOREF )
                {
                    teardown_refs[ i ] = ref;
                    slot = i;
                    break;
                }
            }
        }
        KeReleaseSpinLock( &cb_registry_lock, old );

        if ( slot < 0 )
        {
            luaL_unref( Ls, LUA_REGISTRYINDEX, ref );
            lua_pushboolean( Ls, 0 );
            return 1;
        }

        lua_pushboolean( Ls, 1 );
        return 1;
    }

    static int track_patch( lua_State* Ls )
    {
        uint64_t target = luaL_checkunsigned( Ls, 1 );
        uint64_t replacement = luaL_checkunsigned( Ls, 2 );
        uint8_t width = 8;
        if ( !lua_isnoneornil( Ls, 3 ) )
        {
            uint64_t value = luaL_checkunsigned( Ls, 3 );
            if ( value != 1 && value != 2 && value != 4 && value != 8 )
                return luaL_error( Ls, "patch width must be 1, 2, 4 or 8" );
            width = ( uint8_t ) value;
        }
        if ( target < 0xFFFF800000000000ull )
            return luaL_error( Ls, "patch target is not a canonical kernel address" );

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );

        for ( int i = 0; i < MAX_TRACKED_PATCHES; i++ )
        {
            const tracked_patch& patch = tracked_patches[ i ];
            if ( patch.active && patch.target == target &&
                 patch.replacement == replacement && patch.width == width )
            {
                KeReleaseSpinLock( &cb_registry_lock, old );
                lua_pushunsigned( Ls, i );
                return 1;
            }
            if ( patch.active && patch.target == target )
            {
                KeReleaseSpinLock( &cb_registry_lock, old );
                return luaL_error( Ls, "patch target already tracked" );
            }
        }

        int slot = -1;
        for ( int i = 0; i < MAX_TRACKED_PATCHES; i++ )
        {
            if ( !tracked_patches[ i ].active )
            {
                slot = i;
                break;
            }
        }
        if ( slot < 0 )
        {
            KeReleaseSpinLock( &cb_registry_lock, old );
            return luaL_error( Ls, "tracked patch table is full" );
        }

        uint64_t original = 0;
        if ( !patch_read( target, width, original ) ||
             !patch_write( target, width, replacement ) )
        {
            KeReleaseSpinLock( &cb_registry_lock, old );
            return luaL_error( Ls, "could not read or write patch target" );
        }

        tracked_patches[ slot ] = { target, original, replacement, width, true };
        KeReleaseSpinLock( &cb_registry_lock, old );
        lua_pushunsigned( Ls, slot );
        return 1;
    }

    static int restore_patch( lua_State* Ls )
    {
        uint64_t id = luaL_checkunsigned( Ls, 1 );
        if ( id >= MAX_TRACKED_PATCHES )
            return luaL_error( Ls, "invalid patch id" );

        bool restored = false;
        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        tracked_patch& patch = tracked_patches[ id ];
        if ( patch.active )
        {
            uint64_t current = 0;
            if ( patch_read( patch.target, patch.width, current ) )
            {
                if ( current == patch.replacement )
                    restored = patch_write( patch.target, patch.width, patch.original );
                else
                    InterlockedIncrement64( &patch_conflicts );
                patch.active = false;
            }
        }
        KeReleaseSpinLock( &cb_registry_lock, old );
        lua_pushboolean( Ls, restored );
        return 1;
    }

    static int restore_all_patches_lua( lua_State* Ls )
    {
        lua_pushboolean( Ls, restore_all_patches() );
        return 1;
    }

    static int patch_conflicts_lua( lua_State* Ls )
    {
        lua_pushinteger( Ls, patch_conflicts );
        return 1;
    }

    // SetGate(eid, program | nil)
    //   program: flat array of 5-word instructions produced by gate.compile.
    //            Validated fully before install; a rejected program changes
    //            nothing. nil / no argument clears the gate.
    //
    static int set_gate( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );

        if ( lua_isnoneornil( Ls, 2 ) )
        {
            KIRQL old;
            KeAcquireSpinLock( &cb_registry_lock, &old );
            InterlockedIncrement64( &cb_registry[ event_id ].gate_seq );
            cb_registry[ event_id ].gate_len = 0;
            InterlockedIncrement64( &cb_registry[ event_id ].gate_seq );
            KeReleaseSpinLock( &cb_registry_lock, old );
            return 0;
        }

        luaL_checktype( Ls, 2, LUA_TTABLE );
        size_t words = lua_rawlen( Ls, 2 );
        if ( words == 0 || words % 5 != 0 || words / 5 > MAX_GATE_INSTRS )
            return luaL_error( Ls, "gate program must be 1..%d instructions of 5 words", MAX_GATE_INSTRS );

        LONG count = ( LONG ) ( words / 5 );
        uint64_t staged[ MAX_GATE_INSTRS * 5 ];

        for ( size_t w = 0; w < words; w++ )
        {
            lua_rawgeti( Ls, 2, ( int ) ( w + 1 ) );
            bool is_int = lua_isinteger( Ls, -1 ) != 0;
            uint64_t word = lua_tounsigned( Ls, -1 );
            lua_pop( Ls, 1 );
            if ( !is_int )
                return luaL_error( Ls, "gate word %d is not an integer", ( int ) ( w + 1 ) );
            staged[ w ] = word;
        }

        for ( LONG i = 0; i < count; i++ )
        {
            const uint64_t* c = staged + i * 5;
            uint64_t op = c[ 0 ], unit = c[ 1 ] >> 32, index = c[ 1 ] & 0xFFFFFFFF;

            if ( op > OP_ALLBITS )
                return luaL_error( Ls, "gate instruction %d: bad opcode %d", ( int ) i, ( int ) op );
            if ( unit > 2 )
                return luaL_error( Ls, "gate instruction %d: bad selector unit", ( int ) i );
            if ( unit == 0 && index >= 16 )
                return luaL_error( Ls, "gate instruction %d: arg index out of range", ( int ) i );
            if ( unit == 1 && index > 0xFFF )
                return luaL_error( Ls, "gate instruction %d: stack offset out of range", ( int ) i );
            if ( unit == 2 && index > 0x500 )
                return luaL_error( Ls, "gate instruction %d: thread offset out of range", ( int ) i );
        }

        if ( staged[ ( count - 1 ) * 5 ] != OP_STOP )
            return luaL_error( Ls, "gate program must end with a STOP instruction" );

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        callback_registration& reg = cb_registry[ event_id ];
        InterlockedIncrement64( &reg.gate_seq );
        memcpy( reg.gate_instrs, staged, words * sizeof( uint64_t ) );
        reg.gate_len = count;
        InterlockedIncrement64( &reg.gate_seq );
        KeReleaseSpinLock( &cb_registry_lock, old );

        return 0;
    }

    // SetWait(eid [, ms])
    //   ms > 0: bound any blocking dispatch wait for this event to ms
    //   ms omitted/0: restore defaults (gated 250ms, plain blocking infinite)
    //
    static int set_wait( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );

        uint32_t ms = 0;
        if ( !lua_isnoneornil( Ls, 2 ) )
        {
            lua_Integer v = luaL_checkinteger( Ls, 2 );
            if ( v < 0 || v > 0xFFFFFFFF )
                return luaL_error( Ls, "wait out of range" );
            ms = ( uint32_t ) v;
        }

        KIRQL old;
        KeAcquireSpinLock( &cb_registry_lock, &old );
        cb_registry[ event_id ].wait_ms = ms;
        KeReleaseSpinLock( &cb_registry_lock, old );
        return 0;
    }

    // EventMisses(eid) -> count of dispatches that timed out waiting for the
    // VM lock (cumulative; scripts report deltas).
    //
    static int event_misses( lua_State* Ls )
    {
        int event_id = (int) luaL_checkunsigned( Ls, 1 );
        if ( event_id < 0 || event_id >= MAX_EVENTS )
            return luaL_error( Ls, "invalid event_id %d", event_id );
        lua_pushinteger( Ls, cb_registry[ event_id ].lock_misses );
        return 1;
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

        lua_pushcfunction( Ls, &set_gate );
        lua_setglobal( Ls, "SetGate" );

        lua_pushcfunction( Ls, &set_wait );
        lua_setglobal( Ls, "SetWait" );

        lua_pushcfunction( Ls, &event_misses );
        lua_setglobal( Ls, "EventMisses" );

        lua_pushunsigned( Ls, PASS_THROUGH_SENTINEL );
        lua_setglobal( Ls, "PASS_THROUGH" );

        lua_pushcfunction( Ls, &on_teardown );
        lua_setglobal( Ls, "OnTeardown" );

        lua_pushcfunction( Ls, &track_patch );
        lua_setglobal( Ls, "TrackPatch" );

        lua_pushcfunction( Ls, &restore_patch );
        lua_setglobal( Ls, "RestorePatch" );

        lua_pushcfunction( Ls, &restore_all_patches_lua );
        lua_setglobal( Ls, "RestoreAllPatches" );

        lua_pushcfunction( Ls, &patch_conflicts_lua );
        lua_setglobal( Ls, "PatchConflicts" );
    }
}
