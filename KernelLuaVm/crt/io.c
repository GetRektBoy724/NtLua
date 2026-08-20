#include "crt.h"
#include "../logger.hpp"
#include "../log_ring.hpp"

FILE* __stdcall __acrt_iob_func( unsigned i )
{
    if ( i == 1 ) return FILE_STDOUT;
    if ( i == 2 ) return FILE_STDERR;
    return 0;
}

FILE* freopen( const char* filename, const char* mode, FILE* stream )
{
    return 0;
}

size_t fwrite( const void* ptr, size_t size, size_t count, FILE* stream )
{
    if ( stream == FILE_STDOUT )
    {
        if ( logger::string_buffer* b = logger::log_buffer() )
            b->append_raw( ( const char* ) ptr, size * count );
        log_ring::push( ( const char* ) ptr, size * count );
        return count;
    }
    else if ( stream == FILE_STDERR )
    {
        if ( logger::string_buffer* b = logger::error_buffer() )
            b->append_raw( ( const char* ) ptr, size * count );
        log_ring::push( ( const char* ) ptr, size * count );
        return count;
    }
    return 0;
}

size_t fread( void* ptr, size_t size, size_t count, FILE* stream )
{
    return 0;
}

int getc( FILE* stream )
{
    return -1;
}

FILE* fopen( const char* filename, const char* mode )
{
    return 0;
}

int fflush( FILE* stream )
{
    return 0;
}

int ferror( FILE* stream )
{
    return 1;
}

int feof( FILE* stream )
{
    return 1;
}

int fclose( FILE* stream )
{
    return 1;
}