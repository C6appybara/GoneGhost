#pragma once

typedef NTSTATUS ( NTAPI*fnNtQuerySystemInformation )(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_( SystemInformationLength ) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS ( NTAPI*fnNtQueryDirectoryFile )(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_( Length ) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass,
	_In_ BOOLEAN ReturnSingleEntry,
	_In_opt_ PUNICODE_STRING FileName,
	_In_ BOOLEAN RestartScan
);

typedef NTSTATUS ( NTAPI*fnRtlUnicodeStringToAnsiString )(
	_Inout_ PANSI_STRING DestinationString,
	_In_ PUNICODE_STRING SourceString,
	_In_ BOOLEAN AllocateDestinationString
);

typedef NTSTATUS ( NTAPI *fnNtQueryDirectoryFileEx )(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_writes_bytes_( Length ) PVOID FileInformation,
	_In_ ULONG Length,
	_In_ FILE_INFORMATION_CLASS FileInformationClass,
	_In_ ULONG QueryFlags,
	_In_opt_ PUNICODE_STRING FileName
);

typedef NTSTATUS ( NTAPI *fnNtEnumerateKey )(
	_In_ HANDLE KeyHandle,
	_In_ ULONG Index,
	_In_ NT_KEY_INFORMATION_CLASS KeyInformationClass,
	_Out_writes_bytes_to_opt_( Length, *ResultLength ) PVOID KeyInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
);

typedef NTSTATUS ( NTAPI*fnNtEnumerateValueKey )(
	HANDLE key,
	ULONG index,
	NT_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass,
	LPVOID keyValueInformation,
	ULONG keyValueInformationLength,
	PULONG resultLength
);
