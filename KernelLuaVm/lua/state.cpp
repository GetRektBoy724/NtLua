#include "state.hpp"
#include "../trace_ring.hpp"

namespace lua
{
    struct allocation_header
    {
        uint64_t size;

        static allocation_header* of( void* p ) { return ( ( allocation_header* ) p ) - 1; }

        void* data() { return this + 1; }
        const void* data() const { return this + 1; }
    };

    static void* allocator( void*, void* odata, size_t osize, size_t nsize )
    {
        // If new size is zero:
        //
        if ( !nsize )
        {
            // Deallocate previous if relevant, return null.
            //
            if ( osize ) free( allocation_header::of( odata ) );
            return nullptr;
        }

        // If no old data:
        //
        if ( !odata )
        {
            // Allocate as requested. The header size MUST be written on the
            // first allocation too - lua_realloc later compares against it;
            // leaving it as uninitialized pool garbage handed Lua a block
            // that could be smaller than the size it reported.
            //
            allocation_header* nhdr = ( allocation_header* ) malloc( nsize + sizeof( allocation_header ) );
            if ( !nhdr )
                return nullptr;
            nhdr->size = nsize;
            return nhdr->data();
        }

        // Resolve allocation header of the old data.
        //
        allocation_header* hdr = allocation_header::of( odata );

        // If it can accomadate curent data and is not "substantially" different in size, return as is.
        //
        if ( hdr->size >= nsize && nsize >= ( hdr->size / 2 ) )
            return odata;

        // Calculate the new "ideal" allocation size.
        //
        nsize = max( min( pow( nsize, 1.2 ), PAGE_SIZE ), nsize );

        // Allocate from non-paged pool and write the size. A failed realloc
        // returns NULL without touching the old block - that is the lua_Alloc
        // contract, and Lua turns it into a clean out-of-memory error.
        //
        allocation_header* nhdr = ( allocation_header* ) malloc( nsize + sizeof( allocation_header ) );
        if ( !nhdr )
            return nullptr;
        nhdr->size = nsize;

        // Relocate the old data and free.
        //
        memcpy( nhdr->data(), odata, min( osize, nsize ) );
        free( hdr );

        // Return pointer to the new data.
        //
        return nhdr->data();
    }

    static int panic( lua_State* L )
    {
        const char* message = lua_tostring( L, -1 );
        logger::error( "Runtime error: %s\n", message ? message : "(non-string error object)" );
        lua_context* context = get_context( L );
        if ( context->panic_active &&
             context->panic_owner == ( void* ) KeGetCurrentThread() )
            longjmp( context->panic_jump, 1 );
        return 0;
    }

    // Count hook installed on every VM: once the per-work-unit instruction
    // budget drains, raises a Lua error. Caught by the enclosing lua_pcall
    // (chunks in execute, handlers in run_handler) with a traceback, so an
    // infinite loop aborts cleanly instead of pinning the VM lock.
    //
    static void execution_hook( lua_State* L, lua_Debug* )
    {
        lua_context* context = get_context( L );
        context->budget_remaining -= lua_context::EXECUTION_HOOK_STEP;
        if ( context->budget_remaining <= 0 )
            luaL_error( L, "script exceeded the instruction budget (%lld instructions)",
                        ( long long ) lua_context::EXECUTION_BUDGET );
    }

    // Initializes a Lua state.
    //
    lua_State* init()
    {
        lua_State* L = lua_newstate( &allocator, new lua_context );
        if ( !L ) return nullptr;
        lua_atpanic( L, &panic );
        luaL_openlibs( L );
        lua_sethook( L, &execution_hook, LUA_MASKCOUNT, lua_context::EXECUTION_HOOK_STEP );
        return L;
    }

    // Destroys a Lua state.
    //
    void destroy( lua_State* L )
    {
        lua_context* context = get_context( L );
        lua_close( L );
        delete context;
    }

    // Gets current context from a Lua state.
    //
    lua_context* get_context( lua_State* L )
    {
        void* ctx;
        lua_getallocf( L, &ctx );
        return ( lua_context* ) ctx;
    }

    // Error handler passed to lua_pcall: appends a full stack traceback to the
    // error message so runtime errors report the call stack with line numbers
    // instead of a bare message.
    //
    static int traceback( lua_State* L )
    {
        const char* msg = lua_tostring( L, 1 );
        if ( !msg )
        {
            if ( luaL_callmeta( L, 1, "__tostring" ) && lua_type( L, -1 ) == LUA_TSTRING )
                return 1;
            msg = lua_pushfstring( L, "(error object is a %s value)", luaL_typename( L, 1 ) );
        }
        luaL_traceback( L, L, msg, 1 );
        return 1;
    }

    // Executes code in given Lua state.
    //
    void execute( lua_State* L, const char* code, bool user_input, const char* chunkname )
    {
        size_t len = strlen( code );
        if ( !len ) return;

        // Stack-neutral discipline: handlers can dispatch nested inside this
        // function's live lua_pcall frames (same-thread callback re-entry via
        // the FFI), so every VM entry point must leave the top where it found
        // it, pop what it pushed, and never clear to zero.
        //
        int entry = lua_gettop( L );
        lua_context* context = lua::get_context( L );
        context->budget_remaining = lua_context::EXECUTION_BUDGET;
        context->panic_owner = ( void* ) KeGetCurrentThread();
        context->panic_active = 1;

        // Guard against Lua panic.
        //
        if ( setjmp( lua::get_context( L )->panic_jump ) == 0 )
        {
            // Try to load the buffer.
            //
            if ( luaL_loadbuffer( L, code, len, chunkname ) )
            {
                const char* msg = lua_tostring( L, -1 );
                trace::push( NTLUA_TRK_TRAP, msg ? msg : "parser error", 0, nullptr, 0 );
                logger::error( "Lua parser error: %s\n", msg ? msg : "(non-string error object)" );
                lua_pop( L, 1 );
                context->panic_active = 0;
                context->panic_owner = nullptr;
                return;
            }

            // Guard against any exceptions.
            //
            __try
            {
                // Guard against any virtual exceptions.
                //
                int base = lua_gettop( L );   // chunk is at the top
                lua_pushcfunction( L, &traceback );
                lua_insert( L, base );        // move handler under the chunk

                trace::push( NTLUA_TRK_CALL, chunkname, 0, nullptr, 0 );

                int status = lua_pcall( L, 0, user_input ? LUA_MULTRET : 0, base );
                lua_remove( L, base );        // drop the handler

                if ( status )
                {
                    const char* msg = lua_tostring( L, -1 );
                    trace::push( NTLUA_TRK_TRAP, msg ? msg : "runtime error", 0, nullptr, 0 );
                    logger::error( "Lua runtime error: %s\n", msg ? msg : "(non-string error object)" );
                    lua_pop( L, 1 );
                }
                // If not internal and we have something left on stack:
                //
                else
                {
                    trace::push( NTLUA_TRK_RETURN, chunkname, 0, nullptr, 0 );
                    if ( user_input && lua_gettop( L ) > entry )
                    {
                        // Redirect to print.
                        //
                        lua_getglobal( L, "print" );
                        lua_insert( L, entry + 1 );
                        lua_pcall( L, lua_gettop( L ) - ( entry + 1 ), 0, 0 );
                    }
                }

                lua_settop( L, entry );
            }
            __except ( 1 )
            {
                uint64_t a[ 1 ] = { ( uint64_t ) GetExceptionCode() };
                trace::push( NTLUA_TRK_TRAP, "SEH", 1, a, 0 );
                logger::error( "Lua SEH error: %x\n", GetExceptionCode() );
                lua_settop( L, entry );
            }
        }
        else
        {
            trace::push( NTLUA_TRK_TRAP, "panic", 0, nullptr, 0 );
            logger::error( "Lua Panic!" );
        }

        context->panic_active = 0;
        context->panic_owner = nullptr;
    }
};

// Some helpers we need in Lua style.
//
uint64_t lua_asintrinsic( lua_State* L, int i )
{
    switch ( lua_type( L, i ) )
    {
        case LUA_TSTRING:
            return ( uint64_t ) lua_tostring( L, i );
        case LUA_TLIGHTUSERDATA:
        case LUA_TTABLE:
        case LUA_TFUNCTION:
        case LUA_TUSERDATA:
        case LUA_TTHREAD:
            return ( uint64_t ) lua_topointer( L, i );
        case LUA_TNIL:
        case LUA_TBOOLEAN:
        case LUA_TNUMBER:
        default:
            return lua_tounsigned( L, i );
    }
}

void* lua_adressof( lua_State* L, int i )
{
    switch ( lua_type( L, i ) )
    {
        case LUA_TSTRING:
            return ( void* ) lua_tostring( L, i );
        case LUA_TLIGHTUSERDATA:
        case LUA_TTABLE:
        case LUA_TFUNCTION:
        case LUA_TUSERDATA:
        case LUA_TTHREAD:
            return ( void* ) lua_topointer( L, i );
        case LUA_TNIL:
        case LUA_TBOOLEAN:
        case LUA_TNUMBER:
        default:
            return 0;
    }
}
