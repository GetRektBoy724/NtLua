#pragma once

// Assuming the platform specific header is included already.
#define NTLUA_RUN   CTL_CODE( 0x13, 0x37, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define NTLUA_RESET CTL_CODE( 0x13, 0x38, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define NTLUA_TAIL_TRACE CTL_CODE( 0x13, 0x39, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define NTLUA_TRACE_CTL  CTL_CODE( 0x13, 0x3A, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define NTLUA_TAIL_LOG   CTL_CODE( 0x13, 0x3B, METHOD_BUFFERED, FILE_ANY_ACCESS )

// Shared structures.
//
struct ntlua_result
{
    char* errors;
    char* outputs;
};

// Trace ring: records every host-import invocation plus CALL/RETURN/TRAP
// around chunk and callback execution while tracing is enabled. Polled with
// a sequence protocol (last_seq -> next_seq + dropped) so the ring also
// doubles as a flight recorder that survives a wedged request.
//
#define NTLUA_TRACE_ENTRIES  512
#define NTLUA_TRACE_NAME_LEN 48

// kind field values
#define NTLUA_TRK_IMPORT  1   // host import (nt.* / native_function) invoked
#define NTLUA_TRK_CALL    2   // chunk or callback handler started
#define NTLUA_TRK_RETURN  3   // chunk or callback handler returned
#define NTLUA_TRK_TRAP    4   // error / SEH / panic / budget exceeded

struct ntlua_trace_entry
{
    unsigned long long timestamp_100ns;
    unsigned int       kind;
    unsigned int       thread_id;    // OS TID that made the call
    unsigned int       irql;         // KIRQL at the time
    unsigned int       argc;
    unsigned long long argv[ 4 ];    // up to 4 args captured
    unsigned long long rv;           // return value (or 0)
    char               name[ NTLUA_TRACE_NAME_LEN ];
};

struct ntlua_trace_in
{
    unsigned long long last_seq;     // return entries with seq > last_seq
};

struct ntlua_trace_out
{
    unsigned long long next_seq;     // pass this back as last_seq next time
    unsigned int       count;
    unsigned int       dropped;      // entries lost since last poll (ring wrap)
    ntlua_trace_entry  entries[ NTLUA_TRACE_ENTRIES ];
};

#define NTLUA_TRACE_OFF 0
#define NTLUA_TRACE_ON  1

struct ntlua_trace_ctl_in
{
    unsigned int mode;               // NTLUA_TRACE_OFF / NTLUA_TRACE_ON
};

// Tail log ring: a pollable ring of the most recent text lines written to
// stdout/stderr (Lua print() and error output). The driver accumulates
// fwrite() bytes into a line and commits a slot per newline, so the console
// can show live driver/script output without DbgView - the same sequence
// protocol (last_seq -> next_seq + dropped) as the trace ring.
//
#define NTLUA_LOG_ENTRY_LEN 200
#define NTLUA_LOG_ENTRIES   256

struct ntlua_log_entry
{
    unsigned long long timestamp_100ns;
    char               line[ NTLUA_LOG_ENTRY_LEN ];
};

struct ntlua_log_in
{
    unsigned long long last_seq;     // return entries with seq > last_seq
};

struct ntlua_log_out
{
    unsigned long long next_seq;     // pass this back as last_seq next time
    unsigned int       count;
    unsigned int       dropped;      // entries lost since last poll (ring wrap)
    ntlua_log_entry    entries[ NTLUA_LOG_ENTRIES ];
};
