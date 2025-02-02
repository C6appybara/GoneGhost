#pragma once

BOOL HasPrefix( LPCWSTR str );
BOOL HasPrefixU( UNICODE_STRING str );
BOOL CompareToFileName( PFILE_ID_BOTH_DIR_INFO pFileIdBothDirInfo, const char* fileName );
PVOID CopyMemoryEx( _Inout_ PVOID Destination, _In_ PVOID Source, _In_ SIZE_T Length );
