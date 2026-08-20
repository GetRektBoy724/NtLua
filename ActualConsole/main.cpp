#include <Windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <tuple>
#include <vector>
#include "../KernelLuaVm/driver_io.hpp"

HANDLE device = CreateFileA
(
    "\\\\.\\NtLua",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

// - Instance state -
//
// REPL commands (reset, free-form execute, vm kill with no id) target the
// active instance. Initialized to 0 (legacy instance) for backcompat.
//
static unsigned int active_instance = 0;

static bool instance_exists( unsigned int id )
{
    ntlua_instance_list_out out = {};
    DWORD discarded = 0;
    if ( !DeviceIoControl( device, NTLUA_INSTANCE_LIST, nullptr, 0, &out, sizeof( out ), &discarded, nullptr ) )
        return false;
    for ( unsigned int i = 0; i < out.count; i++ )
        if ( out.ids[ i ] == id )
            return true;
    return false;
}

static bool create_instance()
{
    unsigned int new_id = 0;
    DWORD discarded = 0;
    if ( !DeviceIoControl( device, NTLUA_INSTANCE_CREATE, nullptr, 0, &new_id, sizeof( new_id ), &discarded, nullptr ) )
        return false;
    active_instance = new_id;
    printf( "created instance %u\n", new_id );
    return true;
}

static bool destroy_instance( unsigned int id )
{
    if ( id == 0 )
    {
        printf( "instance 0 is the legacy VM; use 'reset' instead of 'vm kill 0'\n" );
        return false;
    }
    DWORD discarded = 0;
    LONG status = 0;
    if ( !DeviceIoControl( device, NTLUA_INSTANCE_DESTROY, &id, sizeof( id ), &status, sizeof( status ), &discarded, nullptr ) )
        return false;
    if ( status != 0 )
    {
        printf( "vm kill %u: status 0x%08lX\n", id, ( unsigned long ) status );
        return false;
    }
    if ( active_instance == id )
        active_instance = 0;
    printf( "destroyed instance %u\n", id );
    return true;
}

static bool reset_active_instance()
{
    DWORD discarded = 0;
    LONG status = 0;
    if ( !DeviceIoControl( device, NTLUA_INSTANCE_RESET, &active_instance, sizeof( active_instance ), &status, sizeof( status ), &discarded, nullptr ) )
        return false;
    if ( status != 0 )
    {
        printf( "reset instance %u: status 0x%08lX\n", active_instance, ( unsigned long ) status );
        return false;
    }
    printf( "reset instance %u\n", active_instance );
    return true;
}

// - Execution -

static void print_buffer( char* buffer, WORD color )
{
    if ( !buffer ) return;
    SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), color );
    puts( buffer );
    VirtualFree( buffer, 0, MEM_RELEASE );
}

static bool execute_on_instance( unsigned int id, const char* str, bool silent, const char* chunkname = nullptr )
{
    // The driver's INSTANCE_RUN input uses "name\0code\0" when a chunk name
    // is present so errors and tracebacks report the real script path
    // instead of "line".
    //
    std::string run_payload;
    if ( chunkname && *chunkname )
    {
        run_payload = chunkname;
        run_payload += '\0';
    }
    run_payload += str;
    run_payload += '\0';

    auto* in = ( ntlua_instance_run_in* ) malloc( sizeof( ntlua_instance_run_in ) - 1 + run_payload.size() );
    if ( !in )
        return false;
    in->id = id;
    memcpy( in->code, run_payload.data(), run_payload.size() );

    ntlua_instance_run_out out = {};
    DWORD discarded = 0;
    DWORD in_len = ( DWORD )( sizeof( ntlua_instance_run_in ) - 1 + run_payload.size() );
    bool ok = DeviceIoControl( device, NTLUA_INSTANCE_RUN, in, in_len, &out, sizeof( out ), &discarded, nullptr );
    free( in );

    if ( !ok )
        return false;

    if ( silent )
    {
        if ( out.errors ) VirtualFree( out.errors, 0, MEM_RELEASE );
        if ( out.outputs ) VirtualFree( out.outputs, 0, MEM_RELEASE );
    }
    else
    {
        print_buffer( out.errors, 12 );
        print_buffer( out.outputs, 15 );
    }
    return true;
}

// - CLI argument parsing -
//
// Form: ntlua.exe [id] script.lua [more.lua ...]
// - First arg parses as integer -> instance id; must already exist
//   (use 'vm new' interactively first; no auto-create on script load).
// - Otherwise -> legacy mode, target instance 0 with all files.
//
static int parse_cli( int argc, const char** argv, unsigned int& out_id, std::vector<const char*>& out_files )
{
    if ( argc < 2 )
        return 0;

    char* endp = nullptr;
    unsigned long id = strtoul( argv[ 1 ], &endp, 10 );
    if ( endp != argv[ 1 ] && *endp == '\0' && id < NTLUA_MAX_INSTANCES )
    {
        out_id = ( unsigned int ) id;
        if ( argc < 3 )
        {
            printf( "instance id specified but no script given\n" );
            return 1;
        }
        if ( !instance_exists( out_id ) )
        {
            printf( "instance %u does not exist; launch ntlua.exe interactively and run 'vm new' first\n", out_id );
            return 1;
        }
        for ( int n = 2; n < argc; n++ )
            out_files.push_back( argv[ n ] );
        active_instance = out_id;
        return 0;
    }

    out_id = 0;
    active_instance = 0;
    for ( int n = 1; n < argc; n++ )
        out_files.push_back( argv[ n ] );
    return 0;
}

int main( int argc, const char** argv )
{
    if ( device == INVALID_HANDLE_VALUE ) return 1;

    unsigned int cli_id = 0;
    std::vector<const char*> files;
    int parse_status = parse_cli( argc, argv, cli_id, files );
    if ( parse_status != 0 ) return parse_status;

    // If any arguments are given, assume they're lua files and execute them.
    //
    if ( !files.empty() )
    {
        for ( const char* path : files )
        {
            printf( "Running '%s' on instance %u...\n", path, active_instance );

            std::ifstream fs( path );
            if ( !fs )
            {
                printf( "could not open '%s'\n", path );
                continue;
            }
            std::string buffer{ std::istreambuf_iterator<char>( fs ), {} };
            execute_on_instance( active_instance, buffer.data(), false, path );
        }
        // Fall through to the REPL + worker thread so that scripts which
        // registered callbacks (e.g. ProcessMonitor.lua) keep running and
        // events are flushed via the worker.
    }

// No polling here; the kernel driver runs per-instance worker threads.

    // Enter REPL:
    //
    while ( 1 )
    {
        // Reset colors and ask user for input.
        //
        SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 7 );
        std::string buffer;
        std::cout << "[" << active_instance << "] => ";
        std::getline( std::cin, buffer );

        // While shift is being held, allow multiple lines to be inputted.
        //
        while ( GetAsyncKeyState( VK_SHIFT ) & 0x8000 )
        {
            std::string buffer2;
            std::cout << "[" << active_instance << "]    ";
            std::getline( std::cin, buffer2 );
            buffer += "\n" + buffer2;
        }

        // Handle special commands:
        //
        if ( buffer == "clear" )
        {
            system( "cls" );
        }
        else if ( buffer == "cmd" )
        {
            return system( "cmd" );
        }
        else if ( buffer == "exit" )
        {
            return exit( 0 );
        }
        else if ( buffer == "reset" )
        {
            reset_active_instance();
        }
        else if ( buffer.rfind( "vm ", 0 ) == 0 )
        {
            std::istringstream iss( buffer.substr( 3 ) );
            std::string sub;
            iss >> sub;
            if ( sub == "" || sub == "list" )
            {
                ntlua_instance_list_out out = {};
                DWORD discarded = 0;
                if ( DeviceIoControl( device, NTLUA_INSTANCE_LIST, nullptr, 0, &out, sizeof( out ), &discarded, nullptr ) )
                {
                    printf( "%u active instance(s):", out.count );
                    for ( uint32_t i = 0; i < out.count; i++ )
                        printf( " %u%s(w%s)", out.ids[ i ],
                                out.ids[ i ] == active_instance ? "*" : "",
                                out.worker_running[ i ] ? "on" : "off" );
                    printf( "  (active = %u)\n", active_instance );
                }
            }
            else if ( sub == "new" )
            {
                create_instance();
            }
            else if ( sub == "kill" )
            {
                std::string id_str;
                iss >> id_str;
                if ( id_str.empty() )
                    destroy_instance( active_instance );
                else
                {
                    char* endp = nullptr;
                    unsigned long id = strtoul( id_str.c_str(), &endp, 10 );
                    if ( endp == id_str.c_str() || *endp != '\0' || id >= NTLUA_MAX_INSTANCES )
                        printf( "vm kill: invalid instance id '%s'\n", id_str.c_str() );
                    else
                        destroy_instance( ( unsigned int ) id );
                }
            }
            else if ( sub == "switch" )
            {
                std::string id_str;
                iss >> id_str;
                if ( id_str.empty() )
                    printf( "usage: vm switch <id>\n" );
                else
                {
                    char* endp = nullptr;
                    unsigned long id = strtoul( id_str.c_str(), &endp, 10 );
                    if ( endp == id_str.c_str() || *endp != '\0' || id >= NTLUA_MAX_INSTANCES )
                        printf( "vm switch: invalid instance id '%s'\n", id_str.c_str() );
                    else if ( !instance_exists( ( unsigned int ) id ) )
                        printf( "vm switch: instance %lu does not exist\n", id );
                    else
                        active_instance = ( unsigned int ) id;
                }
            }
            else
            {
                printf( "unknown vm command '%s' (try: list, new, kill [id], switch <id>)\n", sub.c_str() );
            }
        }
        else if ( buffer.rfind( "worker ", 0 ) == 0 || buffer == "worker" )
        {
            std::istringstream iss( buffer.substr( 7 ) );
            std::string sub;
            iss >> sub;
            if ( sub == "on" || sub == "off" )
            {
                ntlua_instance_worker_ctl ctl = {};
                ctl.id = active_instance;
                ctl.enable = ( sub == "on" ) ? 1 : 0;
                DWORD discarded = 0;
                if ( DeviceIoControl( device, NTLUA_INSTANCE_WORKER_CTL, &ctl, sizeof( ctl ), nullptr, 0, &discarded, nullptr ) )
                    printf( "worker %s on instance %u\n", ( sub == "on" ) ? "on" : "off", active_instance );
                else
                    printf( "failed to toggle worker\n" );
            }
            else
            {
                // Print the current worker state for the active instance.
                //
                ntlua_instance_list_out out = {};
                DWORD discarded = 0;
                if ( DeviceIoControl( device, NTLUA_INSTANCE_LIST, nullptr, 0, &out, sizeof( out ), &discarded, nullptr ) )
                {
                    for ( unsigned int i = 0; i < out.count; i++ )
                    {
                        if ( out.ids[ i ] == active_instance )
                        {
                            printf( "instance %u: worker %s\n", active_instance, out.worker_running[ i ] ? "on" : "off" );
                            break;
                        }
                    }
                }
            }
        }
        else if ( buffer == "trace on" || buffer == "trace off" )
        {
            ntlua_trace_ctl_in ctl = {};
            ctl.mode = ( buffer == "trace on" ) ? NTLUA_TRACE_ON : NTLUA_TRACE_OFF;
            DWORD discarded = 0;
            DeviceIoControl( device, NTLUA_TRACE_CTL, &ctl, sizeof( ctl ), nullptr, 0, &discarded, nullptr );
            printf( "tracing %s\n", ctl.mode == NTLUA_TRACE_ON ? "on" : "off" );
        }
        else if ( buffer == "trace dump" )
        {
            // Poll the ring from the last sequence and print every entry.
            //
            static uint64_t last_seq = 0;
            ntlua_trace_in in = {};
            ntlua_trace_out out = {};
            in.last_seq = last_seq;
            DWORD discarded = 0;
            if ( DeviceIoControl( device, NTLUA_TAIL_TRACE, &in, sizeof( in ), &out, sizeof( out ), &discarded, nullptr ) )
            {
                if ( out.dropped )
                    printf( "(dropped %u entries)\n", out.dropped );
                for ( uint32_t i = 0; i < out.count; i++ )
                {
                    const auto& e = out.entries[ i ];
                    static const char* kinds[] = { "?", "IMPORT", "CALL", "RETURN", "TRAP" };
                    const char* kind = e.kind <= NTLUA_TRK_TRAP ? kinds[ e.kind ] : "?";
                    printf( "%-6s inst=%u tid=%04u irql=%u %s rv=0x%llX\n",
                            kind, e.instance, e.thread_id, e.irql, e.name, e.rv );
                    if ( e.argc )
                    {
                        printf( "        args: " );
                        for ( uint32_t a = 0; a < e.argc; a++ )
                            printf( "%s0x%llX", a ? ", " : "", e.argv[ a ] );
                        printf( "\n" );
                    }
                }
                printf( "%u trace entries\n", out.count );
                last_seq = out.next_seq;
            }
        }
        else if ( buffer == "log dump" )
        {
            // Poll the log ring from the last sequence and print every line.
            //
            static uint64_t last_seq = 0;
            ntlua_log_in in = {};
            ntlua_log_out out = {};
            in.last_seq = last_seq;
            DWORD discarded = 0;
            if ( DeviceIoControl( device, NTLUA_TAIL_LOG, &in, sizeof( in ), &out, sizeof( out ), &discarded, nullptr ) )
            {
                if ( out.dropped )
                    printf( "(dropped %u log lines)\n", out.dropped );
                for ( uint32_t i = 0; i < out.count; i++ )
                    puts( out.entries[ i ].line );
                printf( "%u log lines\n", out.count );
                last_seq = out.next_seq;
            }
        }
        else
        {
            execute_on_instance( active_instance, buffer.data(), false );
        }
    }
}
