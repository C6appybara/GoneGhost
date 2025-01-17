#pragma once

BOOL HasPrefix(LPCWSTR str);
BOOL HasPrefixU(UNICODE_STRING str);
BOOL CompareToFileName(PFILE_ID_BOTH_DIR_INFO pFileIdBothDirInfo, const char* fileName);