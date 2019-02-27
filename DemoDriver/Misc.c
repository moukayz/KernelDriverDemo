#include "Misc.h"

#include <ntimage.h>
#include <ntstrsafe.h>
#include "Internals.h"
#include "DemoDriver.h"

CONST UCHAR NtosBasePattern[] = { 0x0f, 0x88 ,0xeb ,0xf1, 0x00, 0x00 ,0x48 ,0x8b ,0x54 ,0x24 ,0x28 ,0x48 ,0x8b ,0x0d };
UNICODE_STRING uNameMmGetSystemRoutineAddress = RTL_CONSTANT_STRING( L"MmGetSystemRoutineAddress" );

NTSTATUS EnumProcessApc( PCWSTR ProcessName ) {

	PETHREAD currentThread;
	ULONG pid;

	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	UNICODE_STRING uProcessName;
	PSYSTEM_PROCESS_INFO pProcessInfo = NULL;
	PSYSTEM_PROCESS_INFO pSavedProcessInfo = NULL;

	DbgBreakPoint();
	__try {
		// Find target process
		status = ZwQuerySystemInformation( SystemProcessInformation, 0, bytes, &bytes );

		pSavedProcessInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag( NonPagedPool, bytes, 'tag' );
		if ( !pSavedProcessInfo ) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}
		pProcessInfo = pSavedProcessInfo;
		RtlZeroMemory( pProcessInfo, bytes );

		status = ZwQuerySystemInformation( SystemProcessInformation, pProcessInfo, bytes, &bytes );
		if ( !NT_SUCCESS( status ) )	__leave;

		DbgBreakPoint();
		RtlUnicodeStringInit( &uProcessName, ProcessName );
		for ( ;;) {
			// Got it! 
			if ( RtlCompareUnicodeString( &uProcessName, &pProcessInfo->ImageName, TRUE ) == 0 ) {
				DbgBreakPoint();
				pid = HandleToUlong( pProcessInfo->UniqueProcessId );
				break;
			}

			if ( pProcessInfo->NextEntryOffset )
				pProcessInfo = (PSYSTEM_PROCESS_INFO)( (PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset );
			else
			{
				pid = 0;
				break;
			}
		}

		if ( !pid ) {
			status = STATUS_NOT_FOUND;
			__leave;
		}

		// Iterate through its thread list to list all apcs
		for ( ULONG i = 0; i < pProcessInfo->NumberOfThreads; i++ ) {
			status = PsLookupThreadByThreadId( pProcessInfo->Threads[i].ClientId.UniqueThread, &currentThread );
			if ( !NT_SUCCESS( status ) ) {
				break;
			}

			EnumThreadApc( currentThread );
		}
	}
	__finally {
		if ( pSavedProcessInfo )
			ExFreePoolWithTag( pSavedProcessInfo, 'tag' );
	}

	return status;
}

NTSTATUS EnumThreadApc( PETHREAD Thread ) {
	PKAPC_STATE pApcState;
	PKAPC_STATE pSavedApcState;
	PKAPC pCurrentApc;
	PLIST_ENTRY pApcEntry;
	ULONG apcCount;
	KIRQL oldIrql = { 0 };

	// Only test on win7 !!
	pApcState = (PKAPC_STATE)( (PUCHAR)Thread + 0x50 );
	pSavedApcState = (PKAPC_STATE)( (PUCHAR)Thread + 0x240 );

	if ( !pApcState )
		return STATUS_INVALID_PARAMETER;

	DbgBreakPoint();

	PrintLog(
		"\nThread %p\n"
		"\tCurrentApcState: \n"
		"\t\tKernelApcInProgress: %d\n"
		"\t\tKernelApcPending: %d\n"
		"\t\tUserApcPending: %d\n",
		Thread,
		pApcState->KernelApcInProgress,
		pApcState->KernelApcPending,
		pApcState->UserApcPending );

	// Raise IRQL level to APC level so APC list won't change in enumeration
	KeRaiseIrql( APC_LEVEL, &oldIrql );

	// List kernel-mode Apc
	PrintLog( "\t\tKernelMode APC:\n" );
	pApcEntry = pApcState->ApcListHead[KernelMode].Flink;
	apcCount = 0;
	while ( pApcEntry != &pApcState->ApcListHead[KernelMode] ) {
		pCurrentApc = (PKAPC)CONTAINING_RECORD( pApcEntry, KAPC, ApcListEntry );
		if ( pCurrentApc ) {
			PrintLog(
				"\t\t\tApc %d\n"
				"\t\t\t\tKernelRoutine: %p\n"
				"\t\t\t\tNormalRoutine: %p\n"
				"\t\t\t\tRundownRoutine: %p\n",
				apcCount++,
				pCurrentApc->Reserved[0],
				pCurrentApc->Reserved[1],
				pCurrentApc->Reserved[2] );
		}

		pApcEntry = pApcEntry->Flink;

	}

	// List user-mode Apc
	PrintLog( "\t\tUserMode APC:\n" );
	pApcEntry = pApcState->ApcListHead[UserMode].Flink;
	while ( pApcEntry != &pApcState->ApcListHead[UserMode] ) {
		pCurrentApc = (PKAPC)CONTAINING_RECORD( pApcEntry, KAPC, ApcListEntry );
		if ( pCurrentApc ) {
			PrintLog(
				"\t\t\tApc %d\n"
				"\t\t\t\tKernelRoutine: %p\n"
				"\t\t\t\tNormalRoutine: %p\n"
				"\t\t\t\tRundownRoutine: %p\n",
				apcCount++,
				pCurrentApc->Reserved[0],
				pCurrentApc->Reserved[1],
				pCurrentApc->Reserved[2] );
		}

		pApcEntry = pApcEntry->Flink;
	}

	// Lower IRQL level 
	KeLowerIrql( oldIrql );

	return STATUS_SUCCESS;
}

PVOID GetKernelBase2( PULONG NtosSize ) {
	PVOID pMmGetSystemRoutineAddress = NULL;
	PVOID* pNtosBase = NULL;
	PVOID pPatternStart = NULL;
	ULONG patternSize = sizeof( NtosBasePattern );
	PIMAGE_NT_HEADERS pNtosHeader = NULL;

	DbgBreakPoint();
	pMmGetSystemRoutineAddress = MmGetSystemRoutineAddress( &uNameMmGetSystemRoutineAddress );
	if ( !pMmGetSystemRoutineAddress ) {
		DPRINT( "Get address of MmGetSystemRoutineAddress failed.\n" );
		return NULL;
	}

	pPatternStart = SearchPattern( pMmGetSystemRoutineAddress, MAX_SEARCH_SIZE, NtosBasePattern, patternSize );
	if ( !pPatternStart ) {
		DPRINT( "NtosBase pattern not found!.\n" );
		return NULL;
	}

	pNtosBase = GetAddressFromRelative( (PUCHAR)pPatternStart + patternSize );
	pNtosHeader = RtlImageNtHeader( *pNtosBase );
	if ( !pNtosHeader ) {
		DPRINT( "Bad ntos base, cannot get nt headers.\n" );
		return NULL;
	}

	if ( NtosSize )
		*NtosSize = pNtosHeader->OptionalHeader.SizeOfImage;

	return *pNtosBase;
}