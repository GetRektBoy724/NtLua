#include "native_function.hpp"

// Allocator.
//
native_function* native_function::push( lua_State* L )
{
    // lua_newuserdata returns uninitialized memory; member initializers do
    // not run, so set ret_width explicitly (default: full 64-bit result).
    //
    native_function* fn = ( native_function* ) lua_newuserdata( L, sizeof( native_function ) );
    fn->ret_width = 8;
    luaL_getmetatable( L, export_name );
    lua_setmetatable( L, -2 );
    return fn;
}

// Constructor.
//
int native_function::create( lua_State* L )
{
    native_function* fn = push( L );
    fn->address = ( void* ) luaL_checkunsigned( L, 1 );
    if ( !lua_isnoneornil( L, 2 ) )
    {
        int w = ( int ) luaL_checkunsigned( L, 2 );
        if ( w != 1 && w != 2 && w != 4 && w != 8 )
            return luaL_error( L, "ret_width must be 1, 2, 4 or 8, got %d", w );
        fn->ret_width = ( uint8_t ) w;
    }
    return 1;
}

// Getter.
//
native_function* native_function::check( lua_State* L, int index )
{
    native_function* p;
    luaL_checktype( L, index, LUA_TUSERDATA );
    p = ( native_function* ) luaL_checkudata( L, index, export_name );
    if ( !p )
        luaL_error( L, "Type mismatch, expected [%s]\n", export_name );
    return p;
}

// Member functions.
//
int native_function::get_address( lua_State* L )
{
    lua_pushunsigned( L, ( uint64_t ) ( ( native_function* ) check( L, 1 ) )->address );
    return 1;
}
int native_function::get_set_ret_width( lua_State* L )
{
    native_function* fn = check( L, 1 );
    if ( !lua_isnoneornil( L, 2 ) )
    {
        int w = ( int ) luaL_checkunsigned( L, 2 );
        if ( w != 1 && w != 2 && w != 4 && w != 8 )
            return luaL_error( L, "ret_width must be 1, 2, 4 or 8, got %d", w );
        fn->ret_width = ( uint8_t ) w;
        lua_pushvalue( L, 1 );   // setter form: return self for chaining
        return 1;
    }
    lua_pushunsigned( L, fn->ret_width );
    return 1;
}
int native_function::invoke( lua_State* L )
{
    native_function* fn = ( native_function* ) check( L, 1 );

    // Get number of arguments.
    //
    int n = lua_gettop( L ) - 1;
    if ( n >= 32 )
        luaL_error( L, "Too many arguments provided %d vs maximum of 16\n", n );

    // Recursively create the call frame and call out.
    //
    auto rec = [ & ] <typename... Tx> ( auto&& self, const void* fn, size_t i, Tx... args ) -> uint64_t
    {
        if constexpr ( sizeof...( Tx ) <= 32 )
        {
            if ( i == n )
                return ( ( uint64_t( __stdcall* )( Tx... ) ) fn )( args... );
            else
                return self( self, fn, i + 1, args..., lua_asintrinsic( L, i + 2 ) );
        }
        __assume( 0 );
    };
    uint64_t result = rec( rec, fn->address, 0 );

    // Mask to the declared return width. Sub-width callees (BOOLEAN, UCHAR,
    // KPROCESSOR_MODE...) only define AL/AX, leaving upper RAX bits as
    // whatever was in the register - comparing against those is wrong.
    //
    switch ( fn->ret_width )
    {
        case 1:  result &= 0xFF; break;
        case 2:  result &= 0xFFFF; break;
        case 4:  result &= 0xFFFFFFFF; break;
        default: break;
    }

    // Push the result and return.
    //
    lua_pushunsigned( L, result );
    return 1;
}
int native_function::to_string( lua_State* L )
{
    lua_pushfstring( L, "native_function (0x%p)", check( L, 1 )->address );
    return 1;
}