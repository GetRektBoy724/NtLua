#pragma once
#include "../crt/crt.h"
#include <ntifs.h>
#include "../logger.hpp"

extern "C"
{
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>
};

namespace lua
{
    struct lua_context
    {
        // Jump buffer taken on Lua panic.
        //
        jmp_buf panic_jump = {};
        volatile void* panic_owner = nullptr;
        volatile LONG panic_active = 0;

        // Per-work-unit instruction budget enforced by a count hook
        // (execution_hook in state.cpp). Drained by a runaway script or
        // callback handler, the hook raises a Lua error inside the enclosing
        // lua_pcall instead of wedging the VM lock forever. A blocked native
        // FFI call consumes no instructions, so main.cpp's bounded execution
        // thread (NTLUA_RUN) covers that case.
        //
        static constexpr int64_t EXECUTION_HOOK_STEP = 100000;       // hook fires every N instructions
        static constexpr int64_t EXECUTION_BUDGET    = 1000000000LL; // default budget per work unit
        int64_t budget_remaining = 0;
    };

    // Initializes a Lua state.
    //
    lua_State* init();

    // Destroys a Lua state.
    //
    void destroy( lua_State* L );

    // Gets current context from a Lua state.
    //
    lua_context* get_context( lua_State* L );

    // Executes code in given Lua state.
    //
    void execute( lua_State* L, const char* code, bool user_input = false, const char* chunkname = "line" );
};

// Some helpers we need in Lua style.
//
uint64_t lua_asintrinsic( lua_State* L, int i );
void* lua_adressof( lua_State* L, int i );
