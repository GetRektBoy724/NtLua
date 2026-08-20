#pragma once
#include <ntifs.h>
#include "driver_io.hpp"

// Kernel-side trace ring. Records structured events around VM execution
// (chunk/callback CALL, RETURN, TRAP) when tracing is enabled, so the
// console can watch what a script is doing without DbgView and diagnose
// failures after the fact. The disabled fast path is a single volatile
// read. Sequence-based polling (last_seq -> next_seq + dropped) makes the
// ring a flight recorder that survives a wedged request.
//
namespace trace
{
    inline KSPIN_LOCK ring_lock = {};
    inline bool       ring_ready = false;
    inline ntlua_trace_entry ring[ NTLUA_TRACE_ENTRIES ] = {};
    inline uint64_t   ring_seq  = 0;
    inline uint32_t   ring_head = 0;
    inline volatile LONG mode = NTLUA_TRACE_OFF;

    inline void init()
    {
        KeInitializeSpinLock( &ring_lock );
        ring_ready = true;
    }

    inline bool enabled()
    {
        return mode != NTLUA_TRACE_OFF;
    }

    // Records one event. Callers run at PASSIVE_LEVEL (the VM never executes
    // above it); the spinlock additionally keeps the ring safe from any
    // future non-LL producer.
    //
    inline void push( uint32_t kind, const char* name, uint32_t argc, const uint64_t* argv, uint64_t rv )
    {
        if ( !ring_ready || mode == NTLUA_TRACE_OFF )
            return;

        LARGE_INTEGER ts;
        KeQuerySystemTimePrecise( &ts );

        ntlua_trace_entry e = {};
        e.timestamp_100ns = ( uint64_t ) ts.QuadPart;
        e.kind = kind;
        e.thread_id = ( uint32_t ) ( uintptr_t ) PsGetCurrentThreadId();
        e.irql = ( uint32_t ) KeGetCurrentIrql();
        e.argc = argc > 4 ? 4 : argc;
        for ( uint32_t i = 0; i < e.argc; i++ )
            e.argv[ i ] = argv[ i ];
        e.rv = rv;
        if ( name )
        {
            size_t n = 0;
            while ( name[ n ] && n + 1 < sizeof( e.name ) )
            {
                e.name[ n ] = name[ n ];
                n++;
            }
            e.name[ n ] = 0;
        }

        KIRQL irql;
        KeAcquireSpinLock( &ring_lock, &irql );
        ring[ ring_head ] = e;
        ring_head = ( ring_head + 1 ) % NTLUA_TRACE_ENTRIES;
        ring_seq++;
        KeReleaseSpinLock( &ring_lock, irql );
    }

    // NTLUA_TAIL_TRACE: returns entries with seq > in.last_seq (up to ring
    // capacity) plus a dropped count when the consumer fell behind.
    //
    inline NTSTATUS tail_trace( PIRP irp, PIO_STACK_LOCATION sp )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        size_t in_len = sp->Parameters.DeviceIoControl.InputBufferLength;
        size_t out_len = sp->Parameters.DeviceIoControl.OutputBufferLength;

        if ( !buf || in_len < sizeof( ntlua_trace_in ) || out_len < sizeof( ntlua_trace_out ) )
            return STATUS_INVALID_PARAMETER;

        ntlua_trace_in in;
        RtlCopyMemory( &in, buf, sizeof( in ) );
        ntlua_trace_out* out = ( ntlua_trace_out* ) buf;
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
            if ( available > NTLUA_TRACE_ENTRIES )
            {
                dropped = ( uint32_t ) ( available - NTLUA_TRACE_ENTRIES );
                available = NTLUA_TRACE_ENTRIES;
            }
            uint32_t start = ( ring_head + NTLUA_TRACE_ENTRIES - ( uint32_t ) available ) % NTLUA_TRACE_ENTRIES;
            for ( uint32_t i = 0; i < ( uint32_t ) available; i++ )
                out->entries[ i ] = ring[ ( start + i ) % NTLUA_TRACE_ENTRIES ];
            count = ( uint32_t ) available;
        }

        out->next_seq = seq_here;
        out->count = count;
        out->dropped = dropped;

        KeReleaseSpinLock( &ring_lock, irql );

        irp->IoStatus.Information = sizeof( ntlua_trace_out );
        return STATUS_SUCCESS;
    }

    // NTLUA_TRACE_CTL: switch tracing on/off. Volatile write; takes effect
    // at the next push boundary.
    //
    inline NTSTATUS trace_ctl( PIRP irp, PIO_STACK_LOCATION sp )
    {
        void* buf = irp->AssociatedIrp.SystemBuffer;
        size_t in_len = sp->Parameters.DeviceIoControl.InputBufferLength;

        if ( !buf || in_len < sizeof( ntlua_trace_ctl_in ) )
            return STATUS_INVALID_PARAMETER;

        ntlua_trace_ctl_in in;
        RtlCopyMemory( &in, buf, sizeof( in ) );
        InterlockedExchange( &mode, ( LONG ) ( in.mode == NTLUA_TRACE_ON ? NTLUA_TRACE_ON : NTLUA_TRACE_OFF ) );

        irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }
};
