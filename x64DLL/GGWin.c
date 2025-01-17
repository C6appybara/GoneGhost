#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "GGdef.h"
#include <Shlwapi.h>

BOOL HasPrefix(LPCWSTR str)
{
    return str && !StrCmpNIW(str, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}

BOOL HasPrefixU(UNICODE_STRING str)
{
	return str.Buffer && str.Length / sizeof(WCHAR) >= HIDE_PREFIX_LENGTH && !StrCmpNIW(str.Buffer, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}
