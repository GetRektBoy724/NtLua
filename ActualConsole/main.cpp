#include <Windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <tuple>
#include <mutex>
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
bool execute( const char* str, bool silent, const char* chunkname = nullptr )
{
    // Prefix the code with an optional chunk name ("name\0code\0") so the
    // driver can report the real script path in errors and tracebacks.
    //
    std::string payload;
    const char* code = str;
    if ( chunkname && *chunkname )
    {
        payload.reserve( strlen( chunkname ) + strlen( str ) + 2 );
        payload = chunkname;
        payload += '\0';
        payload += str;
        payload += '\0';
        code = payload.data();
    }

    // Issue the IOCTL. When a chunk name is present the payload has an
    // embedded NUL, so strlen() would stop at the name; send the full
    // payload size (name\0code\0) instead.
    //
    DWORD discarded = 0;
    ntlua_result result = { nullptr, nullptr };
    DWORD len = chunkname && *chunkname ? ( DWORD ) payload.size() : ( DWORD ) ( strlen( str ) + 1 );
    DeviceIoControl( device, NTLUA_RUN, ( void* ) code, len, &result, sizeof( result ), &discarded, nullptr );
    bool had_result = result.outputs != nullptr;

    // If silent, free result and return.
    //
    if ( silent )
    {
        if ( result.outputs ) VirtualFree( result.outputs, 0, MEM_RELEASE );
        if ( result.errors ) VirtualFree( result.errors, 0, MEM_RELEASE );
    }
    // Print each buffer to the console.
    //
    else
    {
        for ( auto& [buffer, color] : { std::pair{ result.errors, 12 },
                                        std::pair{ result.outputs, 15 } } )
        {
            if ( !buffer ) continue;
            SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), color );
            puts( buffer );
            VirtualFree( buffer, 0, MEM_RELEASE );
        }
    }
    return had_result;
}

void worker_thread()
{
    bool prev_success = false;
    while ( 1 )
    {
        Sleep( prev_success ? 100 : 5000 );
        static constexpr char worker_script[] = R"(
            if worker then 
                worker()
            end
        )";
        prev_success = execute( worker_script, false );
    }
}


int main( int argc, const char** argv )
{
    if ( device == INVALID_HANDLE_VALUE ) return 1;

    // If any arguments are given, assume they're lua files and execute them.
    //
    if ( argc >= 2 )
    {
        for ( size_t n = 1; n != argc; n++ )
        {
            printf( "Running '%s'...\n", argv[ n ] );

            std::ifstream fs( argv[ n ] );
            std::string buffer{ std::istreambuf_iterator<char>( fs ), {} };
            execute( buffer.data(), false, argv[ n ] );
        }
        // Fall through to the REPL + worker thread so that scripts which
        // registered callbacks (e.g. ProcessMonitor.lua) keep running and
        // events are flushed via the worker.
    }

    // Start the worker thread.
    //
    std::thread thr( &worker_thread );

    // Enter REPL:
    //
    while ( 1 )
    {
        // Reset colors and ask user for input.
        //
        SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), 7 );
        std::string buffer;
        std::cout << "=> ";
        std::getline( std::cin, buffer );

        // While shift is being held, allow multiple lines to be inputted.
        //
        while ( GetAsyncKeyState( VK_SHIFT ) & 0x8000 )
        {
            std::string buffer2;
            std::cout << "   ";
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
            DWORD discarded = 0;
            DeviceIoControl(
                device,
                NTLUA_RESET,
                &buffer[ 0 ], buffer.size() + 1,
                &discarded, sizeof( discarded ),
                &discarded, nullptr
            );
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
                    printf( "%-6s tid=%04u irql=%u %s rv=0x%llX\n",
                            kind, e.thread_id, e.irql, e.name, e.rv );
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
            execute( buffer.data(), false );
        }
    }
}