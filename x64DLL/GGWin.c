#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "GGdef.h"
#include <Shlwapi.h>

BOOL HasPrefix( LPCWSTR str )
{
	return str && !StrCmpNIW( str, HIDE_PREFIX, HIDE_PREFIX_LENGTH );
}

BOOL HasPrefixU( UNICODE_STRING str )
{
	return str.Buffer && str.Length / sizeof( WCHAR ) >= HIDE_PREFIX_LENGTH && !StrCmpNIW(
		str.Buffer, HIDE_PREFIX, HIDE_PREFIX_LENGTH );
}

PVOID CopyMemoryEx( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length )
{
	PBYTE D = Destination;
	PBYTE S = Source;

	while ( Length-- )
		*D++ = *S++;

	return Destination;
}
