
#include "DemoDriver.h"
#include "Internals.h"

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;
DRIVER_DISPATCH		DriverDispatch;

NTSTATUS EnumProcessApc(PCWSTR ProcessName);
NTSTATUS EnumThreadApc(PETHREAD Thread);
NTSTATUS InjectDll(PINJECT_INFO InjectInfo);
NTSTATUS InjectByApc(HANDLE Pid, UNICODE_STRING Dllpath);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, DriverUnload)
#endif

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING registryPath
)
{
	UNREFERENCED_PARAMETER(registryPath);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceLink;

	DriverObject->MajorFunction[IRP_MJ_CREATE] =
		DriverObject->MajorFunction[IRP_MJ_CLOSE] =
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
	DriverObject->DriverUnload = DriverUnload;

	DbgBreakPoint();
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("TEST: %s: IoCreateDevice failed with status 0x%X\n", __FUNCTION__, status);
		return status;
	}

	RtlInitUnicodeString(&deviceLink, SYMBOLIC_NAME);
	status = IoCreateSymbolicLink(&deviceLink, &deviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("TEST: %s: IoCreateSymbolicLink failed with status 0x%X\n", __FUNCTION__, status);
		IoDeleteDevice(deviceObject);
		return status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;
	//DriverObject->DeviceObject = deviceObject;

	EnumProcessApc(L"winlogon.exe");

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	/*UNREFERENCED_PARAMETER(DriverObject);*/
	UNICODE_STRING	deviceSymLink;
	PAGED_CODE();
	DbgBreakPoint();
	RtlInitUnicodeString(&deviceSymLink, SYMBOLIC_NAME);
	IoDeleteSymbolicLink(&deviceSymLink);
	IoDeleteDevice(DriverObject->DeviceObject);

}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0;
	ULONG outputBufferLength = 0;
	ULONG ioControlCode = 0;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;


	if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
		switch (ioControlCode)
		{
		case IOCTL_ENUM_PROCESS_APC:
			if (inputBufferLength <= MAX_PATH) {
				status = EnumProcessApc((PCWSTR)ioBuffer);
			}
			else {
				status = STATUS_INVALID_PARAMETER;
			}
			break;

		case IOCTL_INJECT_DLL:
			if (inputBufferLength == sizeof(INJECT_INFO)) {
				status = InjectDll((PINJECT_INFO)ioBuffer);
			}
			else
				status = STATUS_INVALID_PARAMETER;
			break;
			 
		default:
			status = STATUS_INVALID_PARAMETER;
			break;
		}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS EnumProcessApc(PCWSTR ProcessName) {
	HANDLE processHandle;
	PEPROCESS process;
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
		RtlInitUnicodeString(&uProcessName, ProcessName);
		for (;;) {
			// Got it! 
			if (RtlCompareUnicodeString(&uProcessName, &pProcessInfo->ImageName, TRUE) == 0) {
				DbgBreakPoint();
				pid = (ULONG)pProcessInfo->UniqueProcessId;
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

	return STATUS_SUCCESS;
}