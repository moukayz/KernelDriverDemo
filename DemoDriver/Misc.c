#include "Misc.h"

#include <ntimage.h>
#include <ntstrsafe.h>
#include "Internals.h"
#include "DemoDriver.h"

extern PDEVICE_OBJECT pDeviceObject;

CONST UCHAR NtosBasePattern[] = { 0x0f, 0x88 ,0xeb ,0xf1, 0x00, 0x00 ,0x48 ,0x8b ,0x54 ,0x24 ,0x28 ,0x48 ,0x8b ,0x0d };
CONST UCHAR KiProcessorBlockPattern[] = { 0x41,0x5d,0x5e,0x5d,0x5b,0xc3,0x41,0x0f,0xb7,0xc1,0x48,0x8d,0x1d };
UNICODE_STRING uNameMmGetSystemRoutineAddress = RTL_CONSTANT_STRING(L"MmGetSystemRoutineAddress");
UNICODE_STRING uNameKeInsertQueueDpc = RTL_CONSTANT_STRING(L"KeInsertQueueDpc");

KDEFERRED_ROUTINE TestNormalDpc;
KDEFERRED_ROUTINE TestTimerDpc;
KDEFERRED_ROUTINE TestImportantDpc;
KDEFERRED_ROUTINE TestAnotherDpc;

PKDPC pNormalDpc = NULL;
PKDPC pImportantDpc = NULL;
PKDPC pTimerDpc = NULL;
PKDPC pAnotherDpc = NULL;
PKTIMER pTimer = NULL;

IO_WORKITEM_ROUTINE TestWorkItemRoutine;
IO_WORKITEM_ROUTINE_EX TestWorkItemRoutineEx;
PIO_WORKITEM WorkItem = NULL;
PIO_WORKITEM WorkItemEx = NULL;

NTSTATUS EnumProcessApc(PCWSTR ProcessName) {

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
		status = ZwQuerySystemInformation(SystemProcessInformation, 0, bytes, &bytes);

		pSavedProcessInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, bytes, 'tag');
		if (!pSavedProcessInfo) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}
		pProcessInfo = pSavedProcessInfo;
		RtlZeroMemory(pProcessInfo, bytes);

		status = ZwQuerySystemInformation(SystemProcessInformation, pProcessInfo, bytes, &bytes);
		if (!NT_SUCCESS(status))	__leave;

		DbgBreakPoint();
		RtlUnicodeStringInit(&uProcessName, ProcessName);
		for (;;) {
			// Got it! 
			if (RtlCompareUnicodeString(&uProcessName, &pProcessInfo->ImageName, TRUE) == 0) {
				DbgBreakPoint();
				pid = HandleToUlong(pProcessInfo->UniqueProcessId);
				break;
			}

			if (pProcessInfo->NextEntryOffset)
				pProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
			else
			{
				pid = 0;
				break;
			}
		}

		if (!pid) {
			status = STATUS_NOT_FOUND;
			__leave;
		}

		// Iterate through its thread list to list all apcs
		for (ULONG i = 0; i < pProcessInfo->NumberOfThreads; i++) {
			status = PsLookupThreadByThreadId(pProcessInfo->Threads[i].ClientId.UniqueThread, &currentThread);
			if (!NT_SUCCESS(status)) {
				break;
			}

			EnumThreadApc(currentThread);
		}
	}
	__finally {
		if (pSavedProcessInfo)
			ExFreePoolWithTag(pSavedProcessInfo, 'tag');
	}

	return status;
}

NTSTATUS EnumThreadApc(PETHREAD Thread) {
	PKAPC_STATE pApcState;
	PKAPC_STATE pSavedApcState;
	PKAPC pCurrentApc;
	PLIST_ENTRY pApcEntry;
	ULONG apcCount;
	KIRQL oldIrql = { 0 };

	// Only test on win7 !!
	pApcState = (PKAPC_STATE)((PUCHAR)Thread + 0x50);
	pSavedApcState = (PKAPC_STATE)((PUCHAR)Thread + 0x240);

	if (!pApcState)
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
		pApcState->UserApcPending);

	// Raise IRQL level to APC level so APC list won't change in enumeration
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	// List kernel-mode Apc
	PrintLog("\t\tKernelMode APC:\n");
	pApcEntry = pApcState->ApcListHead[KernelMode].Flink;
	apcCount = 0;
	while (pApcEntry != &pApcState->ApcListHead[KernelMode]) {
		pCurrentApc = (PKAPC)CONTAINING_RECORD(pApcEntry, KAPC, ApcListEntry);
		if (pCurrentApc) {
			PrintLog(
				"\t\t\tApc %d\n"
				"\t\t\t\tKernelRoutine: %p\n"
				"\t\t\t\tNormalRoutine: %p\n"
				"\t\t\t\tRundownRoutine: %p\n",
				apcCount++,
				pCurrentApc->Reserved[0],
				pCurrentApc->Reserved[1],
				pCurrentApc->Reserved[2]);
		}

		pApcEntry = pApcEntry->Flink;

	}

	// List user-mode Apc
	PrintLog("\t\tUserMode APC:\n");
	pApcEntry = pApcState->ApcListHead[UserMode].Flink;
	while (pApcEntry != &pApcState->ApcListHead[UserMode]) {
		pCurrentApc = (PKAPC)CONTAINING_RECORD(pApcEntry, KAPC, ApcListEntry);
		if (pCurrentApc) {
			PrintLog(
				"\t\t\tApc %d\n"
				"\t\t\t\tKernelRoutine: %p\n"
				"\t\t\t\tNormalRoutine: %p\n"
				"\t\t\t\tRundownRoutine: %p\n",
				apcCount++,
				pCurrentApc->Reserved[0],
				pCurrentApc->Reserved[1],
				pCurrentApc->Reserved[2]);
		}

		pApcEntry = pApcEntry->Flink;
	}

	// Lower IRQL level 
	KeLowerIrql(oldIrql);

	return STATUS_SUCCESS;
}

PVOID GetKernelBase2(PULONG NtosSize) {
	PVOID* pNtosBase = NULL;
	ULONG patternSize = sizeof(NtosBasePattern);
	PIMAGE_NT_HEADERS pNtosHeader = NULL;

	DbgBreakPoint();
	pNtosBase = GetAddressFromRoutineByPattern(NULL, &uNameMmGetSystemRoutineAddress, NtosBasePattern, patternSize);
	if (!pNtosBase) {
		DPRINT("Get pointer to Ntos base failed.\n");
		return NULL;
	}
	
	pNtosHeader = RtlImageNtHeader(*pNtosBase);
	if (!pNtosHeader) {
		DPRINT("Bad ntos base, cannot get nt headers.\n");
		return NULL;
	}

	if (NtosSize)
		*NtosSize = pNtosHeader->OptionalHeader.SizeOfImage;

	return *pNtosBase;
}

PVOID GetKiProcessorBlock() {
	return GetAddressFromRoutineByPattern(
		NULL,
		&uNameKeInsertQueueDpc,
		KiProcessorBlockPattern,
		sizeof(KiProcessorBlockPattern));
}

VOID EnumProcessorDpcs(PVOID pKRCB) {
	PKDPC_DATA dpcDataArray = NULL;
	PLIST_ENTRY currentEntry = NULL;
	PKDPC currentDpc = NULL;
	ULONG count = 0;

	if (!pKRCB)	return;

	dpcDataArray = (PKDPC_DATA)((PUCHAR)pKRCB + OFFSET_DPC_DATA);

	PrintLog("========= Normal DPCs ========\n");
	currentEntry = dpcDataArray[0].DpcListHead.Flink;
	while (currentEntry != &dpcDataArray[0].DpcListHead) {
		currentDpc = CONTAINING_RECORD(currentEntry, KDPC, DpcListEntry);
		PrintLog(
			"DPC %d:\n"
			"\tProcessor: %d\n"
			"\tDeferredRoutine: %p\n"
			"\tDeferredContext: %p\n"
			"\tSystemArgument1: %p\n"
			"\tSystemArgument2: %p\n",
			count++, currentDpc->Number,
			currentDpc->DeferredRoutine, currentDpc->DeferredContext,
			currentDpc->SystemArgument1, currentDpc->SystemArgument2);
		currentEntry = currentEntry->Flink;
	}

	PrintLog("========= Threaded DPCs ========\n");
	currentEntry = dpcDataArray[1].DpcListHead.Flink;
	while (currentEntry != &dpcDataArray[1].DpcListHead) {
		currentDpc = CONTAINING_RECORD(currentEntry, KDPC, DpcListEntry);
		PrintLog(
			"DPC %d:\n"
			"\tProcessor: %d\n"
			"\tDeferredRoutine: %p\n"
			"\tDeferredContext: %p\n"
			"\tSystemArgument1: %p\n"
			"\tSystemArgument2: %p\n",
			count++, currentDpc->Number,
			currentDpc->DeferredRoutine, currentDpc->DeferredContext,
			currentDpc->SystemArgument1, currentDpc->SystemArgument2);
		currentEntry = currentEntry->Flink;
	}

}

VOID EnumAllDpcs() {
	PVOID* pKiProcessorBlock = NULL;
	PVOID pCurrentKprcb = NULL;
	ULONG count = 0;

	pKiProcessorBlock = GetKiProcessorBlock();
	if (!pKiProcessorBlock) {
		DPRINT("Get address of nt!KiProcessorBlock failed.\n");
		return;
	}

	while (*pKiProcessorBlock) {
		PrintLog("============= Processor %d ==============", count++);
		EnumProcessorDpcs(*pKiProcessorBlock++);
	}
	
}

/*
Call stack:
DemoDriver!TestNormalDpc+0x24
nt!KiRetireDpcList+0x1bc
nt!KyRetireDpcList+0x5
nt!KiDispatchInterruptContinue
nt!KiDpcInterrupt+0xcc
nt!KeInsertQueueDpc+0x1dc
DemoDriver!TestSetDpcs+0x12a
DemoDriver!DriverTest+0x15
DemoDriver!DriverEntry+0x1b2
*/
VOID TestNormalDpc(
	_In_     struct _KDPC *Dpc,
	_In_opt_ PVOID        DeferredContext,
	_In_opt_ PVOID        SystemArgument1,
	_In_opt_ PVOID        SystemArgument2) {
	DbgBreakPoint();
	PrintLog("Dpc normal get called.\n");
}

VOID TestImportantDpc(
	_In_     struct _KDPC *Dpc,
	_In_opt_ PVOID        DeferredContext,
	_In_opt_ PVOID        SystemArgument1,
	_In_opt_ PVOID        SystemArgument2) {
	DbgBreakPoint();
	PrintLog("Dpc important get called.\n");
}

/*
Call stack:
DemoDriver!TestTimerDpc+0x24
nt!KiProcessTimerDpcTable+0x66
nt!KiProcessExpiredTimerList+0xc6
nt!KiTimerExpiration+0x1be
nt!KiRetireDpcList+0x277
nt!KiIdleLoop+0x5a
*/
VOID TestTimerDpc(
	_In_     struct _KDPC *Dpc,
	_In_opt_ PVOID        DeferredContext,
	_In_opt_ PVOID        SystemArgument1,
	_In_opt_ PVOID        SystemArgument2) {
	DbgBreakPoint();
	PrintLog("Dpc timer get called.\n");
}

VOID TestAnotherDpc(
	_In_     struct _KDPC *Dpc,
	_In_opt_ PVOID        DeferredContext,
	_In_opt_ PVOID        SystemArgument1,
	_In_opt_ PVOID        SystemArgument2) {
	DbgBreakPoint();
	PrintLog("Dpc another get called.\n");
}

VOID TestSetDpcs() {
	LARGE_INTEGER delay = { 0 };
	BOOLEAN isOk;

	pNormalDpc = ExAllocatePoolWithTag(NonPagedPool, 4 * sizeof(KDPC), 'tag');
	pTimer = ExAllocatePoolWithTag(NonPagedPool, sizeof(KTIMER), 'tag');
	if (!pNormalDpc || !pTimer) {
		DPRINT("Allocate pool for DPC and timer failed.\n");
		return;
	}

	pImportantDpc = &pNormalDpc[1];
	pTimerDpc = &pNormalDpc[2];
	pAnotherDpc = &pNormalDpc[3];

	// Set normal dpc and insert it into current processor
	KeInitializeDpc(pNormalDpc, TestNormalDpc, NULL);
	isOk = KeInsertQueueDpc(pNormalDpc, NULL, NULL);
	if (isOk)
		PrintLog("Insert normal dpc .\n");
	else
		PrintLog("Cannot insert normal dpc.\n");

	// Set important dpc and insert it into current processor
	KeInitializeDpc(pImportantDpc, TestImportantDpc, NULL);
	KeSetImportanceDpc(pImportantDpc, HighImportance);
	isOk = KeInsertQueueDpc(pImportantDpc, NULL, NULL);
	if (isOk)
		PrintLog("Insert important dpc .\n");
	else
		PrintLog("Cannot insert important dpc.\n");

	// Set normal dpc and associate it with a timer
	delay.QuadPart = RELATIVE(SECONDS(5));
	KeInitializeDpc(pTimerDpc, TestTimerDpc, NULL);
	KeInitializeTimer(pTimer);
	isOk = KeSetTimer(pTimer, delay, pTimerDpc);
	if (!isOk)
		PrintLog("Set timer dpc .\n");
	else
		PrintLog("Cannot set timer dpc.\n");

	// Set normal dpc and insert it into another processor ( dual-processor system )
	KeInitializeDpc(pAnotherDpc, TestAnotherDpc, NULL);
	KeSetTargetProcessorDpc(pAnotherDpc, 1);
	isOk = KeInsertQueueDpc(pAnotherDpc, NULL, NULL);
	if (isOk)
		PrintLog("Insert another dpc .\n");
	else
		PrintLog("Cannot insert another dpc.\n");
}

VOID TestRemoveDpcs() {
	KeCancelTimer(pTimer);
	KeRemoveQueueDpc(pNormalDpc);
	KeRemoveQueueDpc(pImportantDpc);
	KeRemoveQueueDpc(pAnotherDpc);
}

/*
DemoDriver!TestWorkItemRoutine+0x1a
nt!IopProcessWorkItem+0x23
nt!ExpWorkerThread+0x111
nt!PspSystemThreadStartup+0x5a
nt!KiStartSystemThread+0x16
*/
VOID TestWorkItemRoutine(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_opt_ PVOID Context) {
	DbgBreakPoint();
	IoFreeWorkItem( WorkItem );
	PrintLog( "Normal WorkItem Routine called.\n" );
}

/*
DemoDriver!TestWorkItemRoutineEx+0x1f
nt!IopProcessWorkItem+0x3d
nt!ExpWorkerThread+0x111
nt!PspSystemThreadStartup+0x5a
nt!KiStartSystemThread+0x16
*/
VOID TestWorkItemRoutineEx(
	_In_ PVOID IoObject,
	_In_opt_ PVOID Context,
	_In_ PIO_WORKITEM IoWorkItem ) {
	DbgBreakPoint();
	IoFreeWorkItem( WorkItemEx );
	PrintLog( "Ex WorkItem Routine called.\n" );

}

VOID TestSetWorkItems() {
	DbgBreakPoint();
	WorkItem = IoAllocateWorkItem( pDeviceObject );
	if ( !WorkItem ) {
		DPRINT( "Cannot allocate work item.\n" );
		return;
	}
	IoQueueWorkItem( WorkItem, TestWorkItemRoutine, DelayedWorkQueue, NULL );

	WorkItemEx = IoAllocateWorkItem( pDeviceObject );
	if ( !WorkItemEx ) {
		DPRINT( "Cannot allocate EX work item.\n" );
		return;
	}
	IoQueueWorkItemEx( WorkItemEx, TestWorkItemRoutineEx, DelayedWorkQueue, NULL );
}
