#pragma once

#include <ntifs.h>

#define DEVICE_NAME	L"\\Device\\DemoDriver"
#define SYMBOLIC_NAME	L"\\??\\DemoDriver"

#define MAX_PATH	260
#define MAX_SEARCH_SIZE 1000
#define CALLBACK_ALTITUDE L"1011"

#define IOCTL_ENUM_PROCESS_APC  \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, \
	METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_INJECT_DLL  \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, \
	METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define PrintLog(format, ...)\
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)	

#define DPRINT(format, ...)\
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ %d-%s ]: ", __LINE__, __FUNCTION__); \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)	

#pragma warning(disable:4189)
#pragma warning(disable:4100)
#pragma warning(disable:4200)


//
// Helper functions
//
PVOID GetUserModule(
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING ModuleName,
	IN BOOLEAN isWow64
);

PVOID GetModuleExport(
	IN PVOID pBase,
	IN PCCHAR name_ord,
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING baseName
);

BOOLEAN CheckProcessTermination( PEPROCESS pProcess );

NTSTATUS GetProcessIdByName( IN PWSTR ProcessName, OUT PULONG Pid );

PVOID GetKernelBase( PULONG pImageSize );

PVOID SearchPattern( PVOID Base, ULONG_PTR MaxSize, PCUCHAR Pattern, ULONG_PTR PatternSize );

PVOID GetAddressFromRelative( PVOID pRelativeOffset );