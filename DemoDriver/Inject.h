#pragma once

#include <ntifs.h>
#include "DemoDriver.h"

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

//
// Inject dll
//
NTSTATUS InjectDll( PINJECT_INFO InjectInfo );
NTSTATUS InjectByApc( PINJECT_INFO InjectInfo );
PINJECT_BUFFER GetNativeCode(
	IN PEPROCESS Process,
	IN PVOID pLdrLoadDll,
	IN PUNICODE_STRING pPath
);
PINJECT_BUFFER GetWow64Code(
	IN PEPROCESS Process,
	IN PVOID pLdrLoadDll,
	IN PUNICODE_STRING pPath
);

NTSTATUS LookupSuitableThread( PEPROCESS Process, PETHREAD* pThread );
