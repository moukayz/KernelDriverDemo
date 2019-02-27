#include "Callbacks.h"

#include <ntstrsafe.h>
#include <ntimage.h>
#include "Internals.h"
#include "DemoDriver.h"

UNICODE_STRING uPsSetCreateProcessNotifyRoutine = RTL_CONSTANT_STRING( L"PsSetCreateProcessNotifyRoutine" );
UNICODE_STRING uPsSetCreateThreadNotifyRoutine = RTL_CONSTANT_STRING( L"PsSetCreateThreadNotifyRoutine" );
UNICODE_STRING uPsSetLoadImageNotifyRoutine = RTL_CONSTANT_STRING( L"PsSetLoadImageNotifyRoutine" );
UNICODE_STRING uNameCmUnregisterCallbacks = RTL_CONSTANT_STRING( L"CmUnRegisterCallback" );
CONST UCHAR ProcessCallbackArrayPattern[] = { 0x66,0x01,0x87,0xc4,0x01,0x00,0x00, 0x4c,0x8d,0x35 };
CONST UCHAR ThreadCallbackArrayPattern[] = { 0xeb, 0x4a, 0x33, 0xdb ,0x48 ,0x8d,0x0d };
CONST UCHAR ImageCallbackArrayPattern[] = { 0xeb ,0x4a ,0x33 ,0xdb,0x48, 0x8d ,0x0d };
CONST UCHAR CmCallbackListPattern[] = { 0x45 ,0x33 ,0xc0 ,0x48 ,0x8d ,0x54 ,0x24 ,0x20 ,0x48 ,0x8d, 0x0d };
CONST UCHAR NotifyMaskPattern[] = { 0xeb ,0xcc ,0xf0 ,0x83 ,0x05 ,0x8b ,0x99 ,0xd9 ,0xff ,0x01 ,0x8b ,0x05 };


PVOID pRegistrationHandle = NULL;
LARGE_INTEGER CmCookie = { 0 };
UNICODE_STRING CallbackAltitude = RTL_CONSTANT_STRING( L"1101" );
extern PVOID pDriverObject;

// Create process notify routine
VOID TestCreateProcessCallback(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create ) {
	//DbgBreakPoint();
	PrintLog( "CreateProcessCallback called.\n" );
}

// Create process notify routine(EX)
VOID TestCreateProcessCallbackEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo ) {
	//DbgBreakPoint();
	PrintLog( "CreateProcessCallbackEx called.\n" );
}

// Create thread notify routine
VOID TestCreateThreadCallback(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create ) {
	//DbgBreakPoint();
	//PrintLog( "CreateThreadCallback called.\n" );
}

// Load image notify routine
VOID TestLoadImageCallback(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,                // pid into which image is being mapped
	_In_ PIMAGE_INFO ImageInfo ) {
	//DbgBreakPoint();
	PrintLog( "LoadImageCallback called.\n" );
}

VOID TestInstallNotifyCallbacks() {
	PsSetCreateProcessNotifyRoutine( TestCreateProcessCallback, FALSE );
	PsSetCreateProcessNotifyRoutineEx( TestCreateProcessCallbackEx, FALSE );
	PsSetCreateThreadNotifyRoutine( TestCreateThreadCallback );
	PsSetLoadImageNotifyRoutine( TestLoadImageCallback );
}

VOID TestRemoveNotifyCallbacks() {
	PsSetCreateProcessNotifyRoutine( TestCreateProcessCallback, TRUE );
	PsSetCreateProcessNotifyRoutineEx( TestCreateProcessCallbackEx, TRUE );
	PsRemoveCreateThreadNotifyRoutine( TestCreateThreadCallback );
	PsRemoveLoadImageNotifyRoutine( TestLoadImageCallback );
}

PVOID GetCreateProcessCallbackArray() {
	PVOID pPsSetCreateProcessNotifyRoutine = NULL;
	PVOID pPspSetCreateProcessNotifyRoutine;
	PVOID pPatterStart = NULL;
	PVOID pProcessCallbackArray = NULL;		// nt!PspCreateProcessNotifyRoutine
	ULONG patternSize = sizeof( ProcessCallbackArrayPattern );
	BOOLEAN found = FALSE;
	ULONG offset = 0;
	LONG_PTR relativeOffset = 0;
	DbgBreakPoint();

	pPsSetCreateProcessNotifyRoutine = MmGetSystemRoutineAddress( &uPsSetCreateProcessNotifyRoutine );
	if ( pPsSetCreateProcessNotifyRoutine == NULL ) {
		PrintLog( "Get address of PsSetCreateProcessNotifyRoutine failed.\n" );
		return NULL;
	}

	relativeOffset = *(PLONG_PTR)( (PUCHAR)pPsSetCreateProcessNotifyRoutine + 4 );
	relativeOffset |= 0xFFFFFFFF00000000;
	pPspSetCreateProcessNotifyRoutine = (PVOID)( relativeOffset + (LONG_PTR)( (PUCHAR)pPsSetCreateProcessNotifyRoutine + 8 ) );

	// Start searching for pattern 
	for ( ; offset < 1000; offset++ ) {
		if ( RtlCompareMemory( ( (PUCHAR)pPspSetCreateProcessNotifyRoutine + offset ), ProcessCallbackArrayPattern, patternSize ) == patternSize ) {
			found = TRUE;
			break;
		}
	}
	if ( !found ) {
		PrintLog( "Get address of PspCreateProcessNotifyRoutine failed.\n" );
		return NULL;
	}

	DbgBreakPoint();
	relativeOffset = *(PLONG_PTR)( (PUCHAR)pPspSetCreateProcessNotifyRoutine + offset + patternSize );
	relativeOffset |= 0xFFFFFFFF00000000;
	pProcessCallbackArray = (PVOID)( relativeOffset + (LONG_PTR)( (PUCHAR)pPspSetCreateProcessNotifyRoutine + offset + patternSize + 4 ) );

	return pProcessCallbackArray;
}

PVOID GetCreateThreadCallbackArray() {
	PVOID pPsSetCreateThreadNotifyRoutine = NULL;
	PVOID pPspCreateThreadNotifyRoutine = NULL;
	PVOID pThreadCallbackArray = NULL;
	ULONG patternSize = sizeof( ThreadCallbackArrayPattern );
	LONG relativeOffset = 0;

	BOOLEAN found = FALSE;
	ULONG offset = 0;

	pPsSetCreateThreadNotifyRoutine = MmGetSystemRoutineAddress( &uPsSetCreateThreadNotifyRoutine );
	if ( !pPsSetCreateThreadNotifyRoutine ) {
		PrintLog( "Get address of PsSetCreateThreadNotifyRoutine failed.\n" );
		return NULL;
	}

	DbgBreakPoint();
	for ( ; offset < 1000; offset++ ) {
		if ( RtlCompareMemory( ( (PUCHAR)pPsSetCreateThreadNotifyRoutine + offset ), ThreadCallbackArrayPattern, patternSize ) == patternSize ) {
			found = TRUE;
			break;
		}
	}
	if ( !found ) {
		PrintLog( "Get address of PspCreateThreadNotifyRoutine failed.\n" );
		return NULL;
	}

	relativeOffset = *(PLONG)( (PUCHAR)pPsSetCreateThreadNotifyRoutine + offset + patternSize );
	pPspCreateThreadNotifyRoutine = (PVOID)( (LONG_PTR)relativeOffset + (LONG_PTR)( (PUCHAR)pPsSetCreateThreadNotifyRoutine + offset + patternSize + 4 ) );

	return pPspCreateThreadNotifyRoutine;
}

PVOID GetLoadImageCallbackArray() {
	PVOID pPspLoadImageNotifyRoutine = NULL;
	PVOID pPsSetLoadImageNotifyRoutine = NULL;
	PVOID pImageCallbackArray = NULL;
	UCHAR patternSize = sizeof( ImageCallbackArrayPattern );
	LONG relativeOffset = 0;

	BOOLEAN found = FALSE;
	ULONG offset = 0;

	pPsSetLoadImageNotifyRoutine = MmGetSystemRoutineAddress( &uPsSetLoadImageNotifyRoutine );
	if ( !pPsSetLoadImageNotifyRoutine ) {
		PrintLog( "Get address of PsSetLoadImageNotifyRoutine failed." );
		return NULL;
	}

	DbgBreakPoint();
	for ( ; offset < 1000; offset++ ) {
		if ( RtlCompareMemory( ( (PUCHAR)pPsSetLoadImageNotifyRoutine + offset ), ImageCallbackArrayPattern, patternSize ) == patternSize ) {
			found = TRUE;
			break;
		}
	}
	if ( !found ) {
		PrintLog( "Get address of PspLoadImageNotifyRoutine failed.\n" );
		return NULL;
	}

	relativeOffset = *(PLONG)( (PUCHAR)pPsSetLoadImageNotifyRoutine + offset + patternSize );
	pPspLoadImageNotifyRoutine = (PVOID)( (LONG_PTR)relativeOffset + (LONG_PTR)pPsSetLoadImageNotifyRoutine + offset + patternSize + 4 );

	return pPspLoadImageNotifyRoutine;
}


PVOID GetNotifyCallbackArray( ULONG CallbackType ) {
	PVOID pCallbackArray = NULL;
	PVOID pSetNotifyRoutine = NULL;
	PCUCHAR pCallbackArrayPattern = NULL;
	PUNICODE_STRING pSetNotifyRoutineName = NULL;
	ULONG patternSize = 0;

	switch ( CallbackType ) {
		case ProcessNotifyCallback:
			pSetNotifyRoutineName = &uPsSetCreateProcessNotifyRoutine;
			pCallbackArrayPattern = ProcessCallbackArrayPattern;
			patternSize = sizeof( ProcessCallbackArrayPattern );
			break;
		case ThreadNotifyCallback:
			pSetNotifyRoutineName = &uPsSetCreateThreadNotifyRoutine;
			pCallbackArrayPattern = ThreadCallbackArrayPattern;
			patternSize = sizeof( ThreadCallbackArrayPattern );
			break;
		case ImageNotifyCallback:
			pSetNotifyRoutineName = &uPsSetLoadImageNotifyRoutine;
			pCallbackArrayPattern = ImageCallbackArrayPattern;
			patternSize = sizeof( ImageCallbackArrayPattern );
			break;
		default:
			break;
	}

	pSetNotifyRoutine = MmGetSystemRoutineAddress( pSetNotifyRoutineName );
	if ( !pSetNotifyRoutine ) {
		DPRINT( "Get XXSetNotifyRoutine failed.\n" );
		return NULL;
	}

	if ( CallbackType == ProcessNotifyCallback ) {
		// PsSetCreateProcessNotifyRoutine and Ex all just jump to internal function nt!PspSetCreateProcessNotifyRoutine
		// So need to get its address first before searching patterns
		pSetNotifyRoutine = GetAddressFromRelative( (PUCHAR)pSetNotifyRoutine + 4 );
	}

	pCallbackArray = GetAddressFromRoutineByPattern( pSetNotifyRoutine, NULL, pCallbackArrayPattern, patternSize );

	return pCallbackArray;
}

VOID EnumNotifyCallbackArray( PVOID CallbackArray, ULONG CallbackType ) {
	ULONG count = 0;
	ULONG maxCount = ( CallbackType == ImageNotifyCallback ) ? MAX_IMAGE_CALLBACKS : MAX_PROCESS_CALLBACKS;
	PEX_CALLBACK_BLOCK pCallbackEntry = NULL;

	for ( ; count < maxCount; count++ ) {
		pCallbackEntry = (PEX_CALLBACK_BLOCK)( (PULONG_PTR)CallbackArray )[count];
		pCallbackEntry = (PEX_CALLBACK_BLOCK)( (ULONG_PTR)pCallbackEntry & 0xFFFFFFFFFFFFFFF0 );	// clean the four less significant bits
		if ( !pCallbackEntry )	continue;

		PrintLog( "Callback %d :\n"
			"\tCallbackRoutine: %p\n"
			"\tExFlags: %d\n",
			count, pCallbackEntry->CallbackRoutine, pCallbackEntry->Context );
	}
}

VOID EnumNotifyCallbacks() {
	PVOID pThreadCallbackArray = NULL;
	PVOID pProcessCallbackArray = NULL;
	PVOID pImageCallbackArray = NULL;

	DbgBreakPoint();
	// Enum thread callbacks
	pThreadCallbackArray = GetNotifyCallbackArray( ThreadNotifyCallback );
	if ( !pThreadCallbackArray ) {
		DPRINT( "Cannot get thread callback array.\n" );
		return;
	}

	PrintLog( "\n============== Thread callback list ================\n" );
	EnumNotifyCallbackArray( pThreadCallbackArray, ThreadNotifyCallback );

	DbgBreakPoint();
	// Enum process callbacks
	pProcessCallbackArray = GetNotifyCallbackArray( ProcessNotifyCallback );
	if ( !pProcessCallbackArray ) {
		DPRINT( "Cannot get process callback array.\n" );
		return;
	}

	PrintLog( "\n============== Image callback list ================\n" );
	EnumNotifyCallbackArray( pProcessCallbackArray, ProcessNotifyCallback );

	DbgBreakPoint();
	// Enum image callbacks
	pImageCallbackArray = GetNotifyCallbackArray( ImageNotifyCallback );
	if ( !pImageCallbackArray ) {
		DPRINT( "Cannot get image callback array.\n" );
		return;
	}
	PrintLog( "\n============== Process callback list ================\n" );
	EnumNotifyCallbackArray( pImageCallbackArray, ImageNotifyCallback );

}

PVOID GetNotifyMask() {
	PVOID pNotifyMask = NULL;
	ULONG patternSize = sizeof( NotifyMaskPattern );

	pNotifyMask = GetAddressFromRoutineByPattern( NULL, &uPsSetLoadImageNotifyRoutine, NotifyMaskPattern, patternSize );
	return pNotifyMask;
}

/*
=====================================
The global variable nt!PspNotifyEnableMask controls whether the corresponding notify callbacks will get called.
Generally when new notify callback inserted into callback array, the corresponding bits in PspNotifyEnableMask will be set automatically according the type of callback.
When the system calling notify callbacks, it first checks whether the bit of corresponding callback type in PspNotifyEnableMask is set,
if so, the system will call all callbacks of that type,
if not, the system just return

PsSetLoadImageNotifyRoutine: bit 0
PsSetCreateProcessNotifyRoutine: bit 1
PsSetCreateProcessNotifyRoutineEx: bit 2
PsSetCreateThreadNotifyRoutine: bit 3
=====================================
*/
BOOLEAN DisableNotifyCallback( ULONG CallbackType ) {
	PVOID pNotifyMask = NULL;
	BOOLEAN isOk = TRUE;

	pNotifyMask = GetNotifyMask();
	if ( !pNotifyMask ) {
		DPRINT( "Get PspNotifyEnableMask failed.\n" );
		return FALSE;
	}

	DbgBreakPoint();
	// Clean bits
	switch ( CallbackType ) {
		case ProcessNotifyCallback:
			InterlockedBitTestAndReset( pNotifyMask, 1 );
			InterlockedBitTestAndReset( pNotifyMask, 2 );
			break;
		case ThreadNotifyCallback:
			InterlockedBitTestAndReset( pNotifyMask, 3 );
			break;
		case ImageNotifyCallback:
			InterlockedBitTestAndReset( pNotifyMask, 0 );
			break;
		default:
			isOk = FALSE;
	}

	return isOk;
}


OB_PREOP_CALLBACK_STATUS
TestPreOperationCallback(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo ) {
	/*if ( PreInfo->ObjectType == *PsProcessType )
		PrintLog( "Process ObPreOperation callback called.\n" );
	else if ( PreInfo->ObjectType == *PsThreadType )
		PrintLog( "Thread ObPreOperation Callback called.\n" );*/
	return OB_PREOP_SUCCESS;
}

VOID
TestPostOperationCallback(
	_In_	PVOID RegistrationContext,
	_Inout_	POB_POST_OPERATION_INFORMATION	PostInfo ) {
	/*if ( PostInfo->ObjectType == *PsProcessType )
		PrintLog( "Process ObPostOperation callback called.\n" );
	else if ( PostInfo->ObjectType == *PsThreadType )
		PrintLog( "Thread ObPostOperatoin callback called.\n" );*/
	return;
}

BOOLEAN TestRegisterObCallbacks() {
	NTSTATUS status;
	OB_OPERATION_REGISTRATION opRegistration[2] = { 0 };
	OB_OPERATION_REGISTRATION threadOpRegistration = { 0 };
	OB_OPERATION_REGISTRATION processOpRegsitration = { 0 };
	OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
	UNICODE_STRING altitude;

	// Process operation
	processOpRegsitration.ObjectType = PsProcessType;
	processOpRegsitration.PreOperation = TestPreOperationCallback;
	processOpRegsitration.PostOperation = TestPostOperationCallback;
	SetFlag( processOpRegsitration.Operations, OB_OPERATION_HANDLE_CREATE );
	SetFlag( processOpRegsitration.Operations, OB_OPERATION_HANDLE_DUPLICATE );

	// Thread operation
	threadOpRegistration.ObjectType = PsThreadType;
	threadOpRegistration.PreOperation = TestPreOperationCallback;
	threadOpRegistration.PostOperation = TestPostOperationCallback;
	SetFlag( threadOpRegistration.Operations, OB_OPERATION_HANDLE_CREATE );
	SetFlag( threadOpRegistration.Operations, OB_OPERATION_HANDLE_DUPLICATE );

	opRegistration[0] = processOpRegsitration;
	opRegistration[1] = threadOpRegistration;

	RtlInitUnicodeString( &altitude, CALLBACK_ALTITUDE );
	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = 2;
	callbackRegistration.Altitude = altitude;
	callbackRegistration.OperationRegistration = opRegistration;

	DbgBreakPoint();
	status = ObRegisterCallbacks(
		&callbackRegistration,
		&pRegistrationHandle );

	if ( !NT_SUCCESS( status ) )
	{
		DPRINT( "Install ob callback failed. status = %x\r\n", status );

		return FALSE;
	}

	DPRINT( "Install process callback successfully.\r\n" );
	return TRUE;
}

VOID TestUnregisterObCallbacks() {
	if ( pRegistrationHandle )
		ObUnRegisterCallbacks( pRegistrationHandle );
	pRegistrationHandle = NULL;
}

VOID EnumObCallback( ULONG CallbackType ) {
	POBJECT_TYPE pObject = NULL;
	POB_CALLBACK_ENTRY callbackEntry = NULL;
	PLIST_ENTRY nextEntry = NULL;
	PLIST_ENTRY callbackListHead = NULL;
	ULONG count = 0;

	switch ( CallbackType ) {
		case ProcessObjectCallback:
			pObject = *PsProcessType;
			break;
		case ThreadObjectCallback:
			pObject = *PsThreadType;
			break;
		case DesktopObjectCallback:
			pObject = *ExDesktopObjectType;
			break;
		default:
			break;
	}

	if ( !pObject ) {
		DPRINT( "Unsupported object type!\n" );
		return;
	}

	DbgBreakPoint();
	callbackListHead = &pObject->CallbackList;
	nextEntry = callbackListHead->Flink;
	while ( nextEntry != callbackListHead ) {
		callbackEntry = CONTAINING_RECORD( nextEntry, OB_CALLBACK_ENTRY, EntryItemList );
		PrintLog(
			"Callback %d\n"
			"\tPreCallback: %p\n"
			"\tPostCallback: %p\n",
			count++, callbackEntry->PreOperation, callbackEntry->PostOperation );
		// Check operation type of the current callback entry
		PrintLog( "\tOperation type: " );
		if ( FlagOn( callbackEntry->Operations, OB_OPERATION_HANDLE_CREATE ) )
			PrintLog( "HANDLE_CREATE " );
		if ( FlagOn( callbackEntry->Operations, OB_OPERATION_HANDLE_DUPLICATE ) )
			PrintLog( "HANDLE_DUPLICATE " );
		PrintLog( "\n" );

		nextEntry = nextEntry->Flink;
	}

}

VOID EnumObCallbacks() {
	PrintLog( "========= Process ob callback ========\n" );
	EnumObCallback( ProcessObjectCallback );

	PrintLog( "========= Thread ob callback ========\n" );
	EnumObCallback( ThreadObjectCallback );
}

BOOLEAN DisableObCallback( ULONG CallbackType ) {
	POBJECT_TYPE pObject = NULL;
	POB_CALLBACK_ENTRY callbackEntry = NULL;
	PLIST_ENTRY nextEntry = NULL;
	PLIST_ENTRY callbackListHead = NULL;
	ULONG count = 0;

	switch ( CallbackType ) {
		case ProcessObjectCallback:
			pObject = *PsProcessType;
			break;
		case ThreadObjectCallback:
			pObject = *PsThreadType;
			break;
		case DesktopObjectCallback:
			pObject = *ExDesktopObjectType;
			break;
		default:
			break;
	}

	if ( !pObject ) {
		DPRINT( "Unsupported object type!\n" );
		return FALSE;
	}

	DbgBreakPoint();
	callbackListHead = &pObject->CallbackList;
	nextEntry = callbackListHead->Flink;
	while ( nextEntry != callbackListHead ) {
		DbgBreakPoint();
		callbackEntry = CONTAINING_RECORD( nextEntry, OB_CALLBACK_ENTRY, EntryItemList );
		// Clear magic bit so callback will not get called.
		InterlockedAnd64( (volatile LONG64*)&callbackEntry->Operations, 0x00000000FFFFFFFF );
		nextEntry = nextEntry->Flink;
	}

	return TRUE;
}

NTSTATUS TestRegistryCallback(
	PVOID CallbackContext,
	PVOID Argument1,
	PVOID Argument2 ) {

	PREG_PRE_OPEN_KEY_INFORMATION pRegInfo = NULL;
	ULONG_PTR regInfoType = (ULONG_PTR)Argument1;

	if ( regInfoType == RegNtPreOpenKey || regInfoType == RegNtPreOpenKeyEx ) {
		pRegInfo = (PREG_PRE_OPEN_KEY_INFORMATION)Argument2;
		//DbgBreakPoint();
		//PrintLog( "Detect: Open registry key < %wZ > \n", pRegInfo->CompleteName );
	}
	return STATUS_SUCCESS;
}

VOID TestRegisterCmCallbacks() {
	NTSTATUS status;
	DbgBreakPoint();
	status = CmRegisterCallbackEx( TestRegistryCallback, &CallbackAltitude, pDriverObject, NULL, &CmCookie, NULL );
	if ( !NT_SUCCESS( status ) )
		DPRINT( "Register registry callback failed. status=0x%x", status );
}

VOID TestUnRegisterCmCallbacks() {
	CmUnRegisterCallback( CmCookie );
}

VOID TestRegistryEvents() {
	UNICODE_STRING keyPath = RTL_CONSTANT_STRING( L"\\Registry\\Machine\\Software" );
	OBJECT_ATTRIBUTES regAttr = { 0 };
	HANDLE keyHandle = NULL;
	NTSTATUS status;

	InitializeObjectAttributes( &regAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );
	DbgBreakPoint();
	status = ZwOpenKey( &keyHandle, KEY_ALL_ACCESS, &regAttr );
	if ( !NT_SUCCESS( status ) ) {
		DPRINT( "Open key failed. status=%x\n", status );
		return;
	}

	ZwClose( keyHandle );
}

PVOID GetCmCallbackList() {
	PVOID pCmCallbackList = NULL;
	ULONG patternSize = sizeof( CmCallbackListPattern );
	DbgBreakPoint();

	pCmCallbackList = GetAddressFromRoutineByPattern( NULL, &uNameCmUnregisterCallbacks, CmCallbackListPattern, patternSize );

	return pCmCallbackList;

}

VOID EnumCmCallbacks() {
	PLIST_ENTRY pCmCallbackList = NULL;
	PLIST_ENTRY nextEntry = NULL;
	PCM_CALLBACK_BLOCK callbackEntry = NULL;
	ULONG count = 0;

	DbgBreakPoint();
	pCmCallbackList = (PLIST_ENTRY)GetCmCallbackList();
	if ( !pCmCallbackList ) {
		DPRINT( "Get CmCallbackList failed.\n" );
		return;
	}

	nextEntry = pCmCallbackList->Flink;
	PrintLog( "\n============== cm callback list ================\n" );
	while ( nextEntry != pCmCallbackList ) {
		callbackEntry = CONTAINING_RECORD( nextEntry, CM_CALLBACK_BLOCK, CallbackList );
		PrintLog(
			"CmCallback %d:\n"
			"\tCookie: %p\n"
			"\tCallbackFunction: %p\n"
			"\tContext: %p\n"
			"\tAltitue: %wZ\n",
			count++, callbackEntry->Cookie, callbackEntry->CallbackFunction, callbackEntry->Context, callbackEntry->Altitude );
		nextEntry = nextEntry->Flink;
	}
}