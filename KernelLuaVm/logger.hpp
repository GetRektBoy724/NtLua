#pragma once
#include <ntifs.h>

extern "C" {
    __declspec( dllimport ) int sprintf_s( char* buffer, size_t sizeOfBuffer, const char* format, ... );
};

// Basic logger implementation.
//
namespace logger
{
    // Flat output buffer with a capture watermark: append() writes at the
    // tail, capture_delta() copies everything since the last capture and
    // advances the watermark, compacting once the consumed head is large.
    // Delta capture - instead of reset-at-chunk-start - is what preserves
    // print() output from callbacks that fire between chunks.
    //
    struct string_buffer
    {
        static constexpr size_t buffer_length = 1024 * 1024 * 16;

        char   raw[ buffer_length ];
        size_t iterator = 0;   // write position
        size_t read_pos = 0;   // watermark: everything before it was captured

        template<typename... T>
        int append( const char* format, T... args )
        {
            int result = sprintf_s( &raw[ iterator ], buffer_length - iterator, format, args... );
            if ( result > 0 )
                iterator += result;
            return result;
        }

        int append_raw( const char* data, size_t len )
        {
            if ( len > ( buffer_length - iterator ) )
                len = buffer_length - iterator;
            memcpy( &raw[ iterator ], data, len );
            iterator += len;
            return ( int ) len;
        }

        void reset()
        {
            iterator = 0;
            read_pos = 0;
        }

        // Copies the unconsumed tail [read_pos, iterator) into dst (at most
        // max bytes) and advances the watermark. Compacts when the consumed
        // head is large so old output never stalls new output.
        //
        size_t capture_delta( char* dst, size_t max )
        {
            size_t avail = iterator - read_pos;
            if ( avail > max ) avail = max;
            if ( avail )
            {
                memcpy( dst, raw + read_pos, avail );
                read_pos += avail;
                if ( read_pos >= buffer_length / 2 )
                {
                    size_t remaining = iterator - read_pos;
                    memmove( raw, raw + read_pos, remaining );
                    iterator = remaining;
                    read_pos = 0;
                }
            }
            return avail;
        }
    };

    // A session is a request-scoped pair of buffers. The execution worker
    // will install per-request sessions as the active destination once the
    // VM is multi-state; today all output lands in the single pool-backed
    // global session. Pool-backed (not image .bss) so the driver image does
    // not reserve 32 MB of virtual memory, and Phase 1 can size sessions per
    // instance.
    //
    struct session
    {
        string_buffer logs;
        string_buffer errors;
    };

    inline session* active = nullptr;   // set under LL by the execution worker
    inline session* global = nullptr;   // pool-backed, see init/shutdown

    inline bool init()
    {
        if ( global ) return true;
        global = ( session* ) ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( session ), 'NtLg' );
        if ( global )
            RtlZeroMemory( global, sizeof( *global ) );   // pool is not zeroed
        return global != nullptr;
    }
    inline void shutdown()
    {
        if ( global ) ExFreePool( global );
        global = nullptr;
        active = nullptr;
    }

    // Returns null before init() (or after shutdown); callers treat it as
    // "no output destination" and drop the write.
    //
    inline string_buffer* log_buffer()   { return active ? &active->logs   : ( global ? &global->logs   : nullptr ); }
    inline string_buffer* error_buffer() { return active ? &active->errors : ( global ? &global->errors : nullptr ); }

    template<typename... T> inline int error( const char* format, T... args )
    { string_buffer* b = error_buffer(); return b ? b->append( format, args... ) : 0; }
    template<typename... T> inline int log( const char* format, T... args )
    { string_buffer* b = log_buffer(); return b ? b->append( format, args... ) : 0; }
};