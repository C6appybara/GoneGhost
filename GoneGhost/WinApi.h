/*-----------------------------------------------------------------------------------------------------
	Memory Manipulation
-----------------------------------------------------------------------------------------------------*/

#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }

// The `extern` keyword sets the `memset` function as an external function.
extern void* __cdecl memset( void*, int, size_t );

// The `#pragma intrinsic(memset)` and #pragma function(memset) macros are Microsoft-specific compiler instructions.
// They force the compiler to generate code for the memset function using a built-in intrinsic function.
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset( void* Destination, int Value, size_t Size )
{
	// logic similar to memset's one
	unsigned char* p = Destination;
	while ( Size > 0 )
	{
		*p = ( unsigned char )Value;
		p++;
		Size--;
	}
	return Destination;
}

#define MemCopy         __movsb                                                // Replacing memcpy
#define MemSet          __stosb                                                // Replacing memset
#define MemZero( p, l ) __stosb( ( char* ) ( ( PVOID ) p ), 0, l )             // Replacing ZeroMemory

/*-----------------------------------------------------------------------------------------------------
	Type Casting
-----------------------------------------------------------------------------------------------------*/

#define C_PTR( x )      ( PVOID )     ( x )         // Type-cast to PVOID
#define U_PTR( x )      ( ULONG_PTR ) ( x )         // Type-cast to ULONG_PTR
