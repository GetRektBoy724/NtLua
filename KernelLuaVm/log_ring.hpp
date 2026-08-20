#pragma once
#include <ntifs.h>
#include "driver_io.hpp"

// Kernel-side tail log ring. Lua print()/error output lands in crt/io.c's
// fwrite(), which streams raw bytes - possibly a partial line at a time.
// This ring accumulates those bytes into a line buffer and commits a slot
// per newline, so the console can poll (NTLUA_TAIL_LOG) the most recent
// lines with the same sequence protocol (last_seq -> next_seq + dropped)
// as the trace ring. It doubles as a flight recorder: output survives a
// wedged request.
//
namespace log_ring
{
    inline KSPIN_LOCK ring_lock = {};
    inline bool       ring_ready = false;
    inline ntlua_log_entry ring[ NTLUA_LOG_ENTRIES ] = {};
    inline uint64_t   ring_seq  = 0;
    inline uint32_t   ring_head = 0;

    // Accumulator for the in-progress line (bytes since the last newline).
    //
    inline char       acc[ NTLUA_LOG_ENTRY_LEN ] = {};
    inline uint32_t   acc_len = 0;

    inline void init()
    {
        KeInitializeSpinLock( &ring_lock );
        ring_ready = true;
    }

    // Feeds bytes into the ring, committing a slot whenever a newline is
    // seen. A trailing partial line (no newline yet) stays in the
    // accumulator and is flushed by the next write or by flush_partial().
    //
    inline void push( const char* data, size_t len )
    {
        if ( !ring_ready || !data || len == 0 )
            return;

        LARGE_INTEGER ts;
        KeQuerySystemTimePrecise( &ts );

        KIRQL irql;
        KeAcquireSpinLock( &ring_lock, &irql );

        for ( size_t i = 0; i < len; i++ )
        {
            char c = data[ i ];
            if ( c == '\n' || c == '\r' )
            {
                // Commit the accumulated line (strip the trailing newline).
                //
                if ( acc_len > 0 )
                {
                    ntlua_log_entry* e = &ring[ ring_head ];
                    e->timestamp_100ns = ( uint64_t ) ts.QuadPart;
                    RtlZeroMemory( e->line, sizeof( e->line ) );
                    RtlCopyMemory( e->line, acc, acc_len < NTLUA_LOG_ENTRY_LEN ? acc_len : NTLUA_LOG_ENTRY_LEN - 1 );
                    ring_head = ( ring_head + 1 ) % NTLUA_LOG_ENTRIES;
                    ring_seq++;
                    acc_len = 0;
                }
            }
            else if ( acc_len + 1 < NTLUA_LOG_ENTRY_LEN )
            {
                acc[ acc_len++ ] = c;
            }
            // else: line too long - drop the overflow bytes.
        }

        KeReleaseSpinLock( &ring_lock, irql );
    }

    // Flushes any trailing partial line (e.g. on request end) so output that
    // never got a newline still appears. Safe to call at any time.
    //
    inline void flush_partial()
    {
        if ( !ring_ready || acc_len == 0 )
            return;

        LARGE_INTEGER ts;
        KeQuerySystemTimePrecise( &ts );

        KIRQL irql;
        KeAcquireSpinLock( &ring_lock, &irql );

        if ( acc_len > 0 )
        {
            ntlua_log_entry* e = &ring[ ring_head ];
            e->timestamp_100ns = ( uint64_t ) ts.QuadPart;
            RtlZeroMemory( e->line, sizeof( e->line ) );
            RtlCopyMemory( e->line, acc, acc_len < NTLUA_LOG_ENTRY_LEN ? acc_len : NTLUA_LOG_ENTRY_LEN - 1 );
            ring_head = ( ring_head + 1 ) % NTLUA_LOG_ENTRIES;
            ring_seq++;
            acc_len = 0;
        }

        KeReleaseSpinLock( &ring_lock, irql );
    }

    // NTLUA_TAIL_LOG: returns lines with seq > in.last_seq (up to ring
    // capacity) plus a dropped count when the consumer fell behind.
    //
    inline NTSTATUS tail_log( PIRP irp, PIO_STACK_LOCATION sp )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        size_t in_len = sp->Parameters.DeviceIoControl.InputBufferLength;
        size_t out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;

        if ( !buf || in_len < sizeof( ntlua_log_in ) || out_len < sizeof( ntlua_log_out ) )
            return STATUS_INVALID_PARAMETER;

        ntlua_log_in in;
        RtlCopyMemory( &in, buf, sizeof( in ) );
        ntlua_log_out* out = ( ntlua_log_out* ) buf;
        RtlZeroMemory( out, sizeof( *out ) );

        KIRQL irql;
        KeAcquireSpinLock( &ring_lock, &irql );

        uint64_t seq_here = ring_seq;
        uint64_t want = in.last_seq;
        uint32_t count = 0;
        uint32_t dropped = 0;

        if ( seq_here > want )
        {
            uint64_t available = seq_here - want;
            if ( available > NTLUA_LOG_ENTRIES )
            {
                dropped = ( uint32_t ) ( available - NTLUA_LOG_ENTRIES );
                available = NTLUA_LOG_ENTRIES;
            }
            uint32_t start = ( ring_head + NTLUA_LOG_ENTRIES - ( uint32_t ) available ) % NTLUA_LOG_ENTRIES;
            for ( uint32_t i = 0; i < ( uint32_t ) available; i++ )
                out->entries[ i ] = ring[ ( start + i ) % NTLUA_LOG_ENTRIES ];
            count = ( uint32_t ) available;
        }

        out->next_seq = seq_here;
        out->count = count;
        out->dropped = dropped;

        KeReleaseSpinLock( &ring_lock, irql );

        irp->IoStatus.Information = sizeof( ntlua_log_out );
        return STATUS_SUCCESS;
    }
};
