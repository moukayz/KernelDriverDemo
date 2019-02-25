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


typedef enum _INJECT_TYPE {
	ApcInject
}INJECT_TYPE, *PINJECT_TYPE;

typedef struct _INJECT_INFO {
	ULONG Pid;
	ULONG Type;
	WCHAR Dllpath[MAX_PATH];
	WCHAR Dllpath32[MAX_PATH];
}INJECT_INFO, *PINJECT_INFO;

typedef struct _INJECT_BUFFER
{
	UCHAR code[0x200];
	union
	{
		UNICODE_STRING path;
		UNICODE_STRING32 path32;
	};

	WCHAR buffer[488];
	PVOID module;
	ULONG complete;
	NTSTATUS status;
} INJECT_BUFFER, *PINJECT_BUFFER;

typedef struct _EX_CALLBACK_BLOCK {
	ULONG_PTR RundownProtect;
	PVOID CallbackRoutine;
	ULONG_PTR Context;
}EX_CALLBACK_BLOCK, *PEX_CALLBACK_BLOCK;

typedef enum _CALLBACK_ROUTINE_TYPE {
	ProcessNotifyCallback = 0,
	ThreadNotifyCallback,
	ImageNotifyCallback,
	ProcessObjectCallback,
	ThreadObjectCallback,
	DesktopObjectCallback
}CALLBACK_ROUTINE_TYPE;

#define MAX_PROCESS_CALLBACKS	0x40
#define MAX_THREAD_CALLBACKS	0x40
#define MAX_IMAGE_CALLBACKS		0x8


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