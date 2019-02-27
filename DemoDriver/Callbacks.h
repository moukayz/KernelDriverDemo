#pragma once

#include <ntifs.h>

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
// Enum notify routine
// 
VOID TestCreateProcessCallback(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create );

VOID TestCreateProcessCallbackEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo );

VOID TestLoadImageCallback(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo );

VOID TestCreateThreadCallback(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create );
PVOID GetCreateProcessCallbackArray();
PVOID GetCreateThreadCallbackArray();
PVOID GetLoadImageCallbackArray();
VOID TestInstallNotifyCallbacks();
VOID TestRemoveNotifyCallbacks();
VOID EnumNotifyCallbackArray( PVOID CallbackArray, ULONG CallbackType );
VOID EnumNotifyCallbacks();
PVOID GetPspInitializeCallbacks();
PVOID GetNotifyCallbackArray( ULONG CallbackType );
PVOID GetNotifyMask();
BOOLEAN DisableNotifyCallback( ULONG CallbackType );

//
// Enum object callbacks registered by ObRegisterCallbacks
//
OB_PREOP_CALLBACK_STATUS
TestPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);
VOID
TestPostOperationCallback(
	_In_	PVOID RegistrationContext,
	_Inout_	POB_POST_OPERATION_INFORMATION	PostInfo
);
VOID EnumObCallbacks();
VOID EnumObCallback( ULONG CallbackType );
VOID TestUnregisterObCallbacks();
BOOLEAN TestRegisterObCallbacks();
BOOLEAN DisableObCallback( ULONG CallbackType );

//
// Enum registry callbacks registered by CmRegisterCallbacks
//
EX_CALLBACK_FUNCTION TestRegistryCallback;
VOID TestRegisterCmCallbacks();
VOID TestUnRegisterCmCallbacks();
VOID TestRegistryEvents();
PVOID GetCmCallbackList();
VOID EnumCmCallbacks();
BOOLEAN DisableCmCallbacks();
