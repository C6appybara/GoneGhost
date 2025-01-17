#include <windows.h>
#include <stdio.h>
#include "GGdef.h"
#include <Shlwapi.h>

BOOL HasPrefix(LPCWSTR str)
{
    return str && !StrCmpNIW(str, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}