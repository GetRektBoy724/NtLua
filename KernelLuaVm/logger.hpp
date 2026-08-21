#pragma once
#include <ntifs.h>
#include "crt/stdint.h"
#include "log_ring.hpp"

extern "C" {
    __declspec( dllimport ) int sprintf_s( char* buffer, size_t sizeOfBuffer, const char* format, ... );
};

// Basic logger implementation.
//
namespace logger
{
    // Flat output buffer. append()/append_raw() write at the tail; the execution
    // worker captures a [start, iterator) slice and then drains the whole
    // buffer (read_pos = iterator) so output from worker polls / callbacks
    // that fired between chunks never surfaces in a later REPL return.
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

    // Per-thread output routing.
    //
    // A chunk of Lua execution (REPL, a callback handler, or a worker poll)
    // must route its print()/logger writes into the instance's session. That
    // routing lives in a small thread-keyed table rather than a single global
    // because the driver runs several threads - multiple per-instance worker
    // threads, IRP execution threads and callback dispatch threads - which can
    // execute Lua chunks CONCURRENTLY on different instances. A shared global
    // "active session" would let instance A's thread route output into
    // instance B's session (a data race). __declspec(thread) cannot be used
    // here (forbidden under /kernel), so each thread registers its current
    // session in a fixed table while it runs a chunk.
    //
    struct route_slot
    {
        void*    thread = nullptr;      // ETHREAD*
        int      depth  = 0;
        session* sess[ 4 ] = {};        // nesting stack (nested re-entry on one thread)
    };
    inline route_slot route_table[ 16 ] = {};
    inline KSPIN_LOCK route_lock = { 0 };
    inline session* global = nullptr;   // pool-backed, see init/shutdown

    inline void route_begin( session* sess )
    {
        if ( !sess ) return;
        KIRQL irql;
        KeAcquireSpinLock( &route_lock, &irql );
        void* self = KeGetCurrentThread();
        for ( int i = 0; i < 16; i++ )
        {
            if ( route_table[ i ].thread == self )
            {
                if ( route_table[ i ].depth < 4 )
                    route_table[ i ].sess[ route_table[ i ].depth++ ] = sess;
                break;
            }
            if ( !route_table[ i ].thread )
            {
                route_table[ i ].thread = self;
                route_table[ i ].depth  = 1;
                route_table[ i ].sess[ 0 ] = sess;
                break;
            }
        }
        KeReleaseSpinLock( &route_lock, irql );
    }

    inline void route_end()
    {
        KIRQL irql;
        KeAcquireSpinLock( &route_lock, &irql );
        void* self = KeGetCurrentThread();
        for ( int i = 0; i < 16; i++ )
        {
            if ( route_table[ i ].thread == self )
            {
                if ( route_table[ i ].depth > 0 )
                    route_table[ i ].depth--;
                if ( route_table[ i ].depth == 0 )
                {
                    route_table[ i ].thread = nullptr;
                    route_table[ i ].sess[ 0 ] = nullptr;
                }
                break;
            }
        }
        KeReleaseSpinLock( &route_lock, irql );
    }

    inline session* current_session()
    {
        void* self = KeGetCurrentThread();
        for ( int i = 0; i < 16; i++ )
        {
            if ( route_table[ i ].thread == self && route_table[ i ].depth > 0 )
                return route_table[ i ].sess[ route_table[ i ].depth - 1 ];
        }
        return global;
    }
    inline string_buffer* log_buffer()   { session* s = current_session(); return s ? &s->logs   : nullptr; }
    inline string_buffer* error_buffer() { session* s = current_session(); return s ? &s->errors : nullptr; }

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
        for ( int i = 0; i < 16; i++ )
        {
            route_table[ i ].thread = nullptr;
            route_table[ i ].depth  = 0;
            for ( int k = 0; k < 4; k++ )
                route_table[ i ].sess[ k ] = nullptr;
        }
    }

    // Returns null before init() (or after shutdown); callers treat it as
    // "no output destination" and drop the write.
    //
    template<typename... T> inline int error( const char* format, T... args )
    {
        string_buffer* b = error_buffer();
        if ( !b )
            return 0;
        int n = b->append( format, args... );
        // Mirror the bytes just written to the tail-log ring (single format,
        // full length - the ring itself drops overflow past its slot width).
        // log_ring::push is no-op if the ring is uninitialised.
        //
        if ( n > 0 )
            log_ring::push( b->raw + ( b->iterator - ( size_t ) n ), ( size_t ) n );
        return n;
    }
    template<typename... T> inline int log( const char* format, T... args )
    { string_buffer* b = log_buffer(); return b ? b->append( format, args... ) : 0; }
};