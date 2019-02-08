
#include "DemoDriver.h"

#include <ntstrsafe.h>
#include "Internals.h"

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;
DRIVER_DISPATCH		DriverDispatch;

//
// Enum process APCs
//
NTSTATUS EnumProcessApc(PCWSTR ProcessName);
NTSTATUS EnumThreadApc(PETHREAD Thread);

//
// Inject dll
//
NTSTATUS InjectDll(PINJECT_INFO InjectInfo);
NTSTATUS InjectByApc(PINJECT_INFO InjectInfo);
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
// Kernel routine for inject apc
VOID KernelApcInjectCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);
// Kernel routine for prepare apc
VOID KernelApcPrepareCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);
NTSTATUS LookupSuitableThread(PEPROCESS Process, PETHREAD* pThread);


#define DLL_PATH L"C:\\Users\\MOUKA\\Desktop\\TestDll.dll"

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
	RtlUnicodeStringInit(&deviceName, DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("TEST: %s: IoCreateDevice failed with status 0x%X\n", __FUNCTION__, status);
		return status;
	}

	RtlUnicodeStringInit(&deviceLink, SYMBOLIC_NAME);
	status = IoCreateSymbolicLink(&deviceLink, &deviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("TEST: %s: IoCreateSymbolicLink failed with status 0x%X\n", __FUNCTION__, status);
		IoDeleteDevice(deviceObject);
		return status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;
	//DriverObject->DeviceObject = deviceObject;

	//
	// TEST
	//

	//EnumProcessApc(L"winlogon.exe");
	INJECT_INFO injectInfo = { 0 };
	injectInfo.Pid = 1640;
	RtlStringCbCopyW(injectInfo.Dllpath, MAX_PATH, DLL_PATH);
	
	InjectByApc(&injectInfo);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	/*UNREFERENCED_PARAMETER(DriverObject);*/
	UNICODE_STRING	deviceSymLink;
	PAGED_CODE();
	DbgBreakPoint();
	RtlUnicodeStringInit(&deviceSymLink, SYMBOLIC_NAME);
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

NTSTATUS InjectDll(PINJECT_INFO InjectInfo) {
	NTSTATUS status;
	UNICODE_STRING uDllpath;

	if (!InjectInfo)
		return STATUS_INVALID_PARAMETER;

	status = RtlUnicodeStringInit(&uDllpath, InjectInfo->Dllpath);
	if (!NT_SUCCESS(status))
		return status;

	switch (InjectInfo->Type)
	{
	case ApcInject:
		status = InjectByApc(InjectInfo);
		break;

	default:
		break;
	}

	return status;
}

UNICODE_STRING uNtdll = RTL_CONSTANT_STRING(L"NTDLL.DLL");
#define CALL_COMPLETE   0xC0371E7E

NTSTATUS InjectByApc(PINJECT_INFO InjectInfo) {
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PETHREAD pTargetThread = NULL;
	KAPC_STATE oldApc = { 0 };

	WCHAR dllpath[MAX_PATH];
	UNICODE_STRING uDllpath;
	PVOID pNtdll = NULL;
	PVOID pLdrLoadDll = NULL;
	BOOLEAN isWow64;

	SIZE_T size = 0;
	PINJECT_BUFFER pInjectBuffer = NULL;

	PKAPC pPrepareApc = NULL;
	PKAPC pInjectApc = NULL;

	status = PsLookupProcessByProcessId(ULongToHandle(InjectInfo->Pid), &pProcess);
	if (!NT_SUCCESS(status))
		return status;

	DbgBreakPoint();
	__try {
		isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;
		if (isWow64)
			status = RtlStringCbCopyW(dllpath, MAX_PATH, InjectInfo->Dllpath32);
		else
			status = RtlStringCbCopyW(dllpath, MAX_PATH, InjectInfo->Dllpath);
		if (!NT_SUCCESS(status))	__leave;

		status = RtlUnicodeStringInit(&uDllpath, dllpath);
		if (!NT_SUCCESS(status))	__leave;

		if (CheckProcessTermination(PsGetCurrentProcess()))
		{
			status = STATUS_PROCESS_IS_TERMINATING;
			__leave;
		}

		KeStackAttachProcess(pProcess, &oldApc);

		pNtdll = GetUserModule(pProcess, &uNtdll, isWow64);
		if (!pNtdll) {
			status = STATUS_NOT_FOUND;
			__leave;
		}

		pLdrLoadDll = GetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);
		if (!pLdrLoadDll) {
			status = STATUS_NOT_FOUND;
			__leave;
		}

		//KeUnstackDetachProcess(&oldApc);
		//RtlSecureZeroMemory(&oldApc, sizeof(KAPC_STATE));
		DbgBreakPoint();

		pInjectBuffer = isWow64 ? GetWow64Code(pProcess, pLdrLoadDll, &uDllpath) : GetNativeCode(pProcess, pLdrLoadDll, &uDllpath);
		if (!pInjectBuffer) {
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		status = LookupSuitableThread(pProcess, &pTargetThread);
		if (!NT_SUCCESS(status))
			__leave;

		// Queue user apc to target thread
		pInjectApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'tag');
		pPrepareApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'tag');
		if (!pInjectApc || !pPrepareApc) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// Initailize apc
		KeInitializeApc(
			pInjectApc,
			(PKTHREAD)pTargetThread,
			OriginalApcEnvironment, &KernelApcInjectCallback,
			NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)pInjectBuffer->code, UserMode, NULL);

		KeInitializeApc(
			pPrepareApc, (PKTHREAD)pTargetThread,
			OriginalApcEnvironment, &KernelApcPrepareCallback,
			NULL, NULL, KernelMode, NULL);

		// Insert apc
		KeInsertQueueApc(pInjectApc, NULL, NULL, 0);
		KeInsertQueueApc(pPrepareApc, NULL, NULL, 0);

		// Wait for completion
		LARGE_INTEGER interval = { 0 };
		interval.QuadPart = -(5LL * 10 * 1000);

		for (ULONG i = 0; i < 10000; i++)
		{
			if (CheckProcessTermination(PsGetCurrentProcess()) || PsIsThreadTerminating(pTargetThread))
			{
				status = STATUS_PROCESS_IS_TERMINATING;
				break;
			}

			if (pInjectBuffer->complete == CALL_COMPLETE)
				break;

			if (!NT_SUCCESS(status = KeDelayExecutionThread(KernelMode, FALSE, &interval)))
				break;
		}

		if (NT_SUCCESS(status))
			status = pInjectBuffer->status;
	}
	__finally {
		/*if (pPrepareApc)
			ExFr eePoolWithTag(pPrepareApc, 'tag');

		if (pInjectApc)
			ExFreePoolWithTag(pInjectApc, 'tag');*/

		if (pInjectBuffer)
			ZwFreeVirtualMemory(ZwCurrentProcess(), &pInjectBuffer, &size, MEM_RELEASE);

		// oldApc not zeroed, so target process is still attached
		if (oldApc.ApcListHead[0].Flink)
			KeUnstackDetachProcess(&oldApc);

		if (pTargetThread)
			ObDereferenceObject(pTargetThread);

		if (pProcess)
			ObDereferenceObject(pProcess);
	}

	return status;
}

PINJECT_BUFFER GetWow64Code(
	IN PEPROCESS Process,
	IN PVOID pLdrLoadDll,
	IN PUNICODE_STRING pPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE ProcessHandle;
	PINJECT_BUFFER pBuffer = NULL;
	SIZE_T size = PAGE_SIZE;

	// Code
	UCHAR code[] =
	{
		0x68, 0, 0, 0, 0,                       // push ModuleHandle            offset +1 
		0x68, 0, 0, 0, 0,                       // push ModuleFileName          offset +6
		0x6A, 0,                                // push Flags  
		0x6A, 0,                                // push PathToFile
		0xE8, 0, 0, 0, 0,                       // call LdrLoadDll              offset +15
		0xBA, 0, 0, 0, 0,                       // mov edx, COMPLETE_OFFSET     offset +20
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [edx], CALL_COMPLETE     
		0xBA, 0, 0, 0, 0,                       // mov edx, STATUS_OFFSET       offset +31
		0x89, 0x02,                             // mov [edx], eax
		0xC2, 0x04, 0x00                        // ret 4
	};

	status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);

	status = ZwAllocateVirtualMemory(ProcessHandle, &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		// Copy path
		PUNICODE_STRING32 pUserPath = &pBuffer->path32;
		pUserPath->Length = pPath->Length;
		pUserPath->MaximumLength = pPath->MaximumLength;
		pUserPath->Buffer = (ULONG)(ULONG_PTR)pBuffer->buffer;

		// Copy path
		memcpy((PVOID)pUserPath->Buffer, pPath->Buffer, pPath->Length);

		// Copy code
		memcpy(pBuffer, code, sizeof(code));

		// Fill stubs
		*(ULONG*)((PUCHAR)pBuffer + 1) = (ULONG)(ULONG_PTR)&pBuffer->module;
		*(ULONG*)((PUCHAR)pBuffer + 6) = (ULONG)(ULONG_PTR)pUserPath;
		*(ULONG*)((PUCHAR)pBuffer + 15) = (ULONG)((ULONG_PTR)pLdrLoadDll - ((ULONG_PTR)pBuffer + 15) - 5 + 1);
		*(ULONG*)((PUCHAR)pBuffer + 20) = (ULONG)(ULONG_PTR)&pBuffer->complete;
		*(ULONG*)((PUCHAR)pBuffer + 31) = (ULONG)(ULONG_PTR)&pBuffer->status;

		return pBuffer;
	}
	
	if (ProcessHandle)
		ZwClose(ProcessHandle);

	return NULL;

}

PINJECT_BUFFER GetNativeCode(
	IN PEPROCESS Process,
	IN PVOID pLdrLoadDll,
	IN PUNICODE_STRING pPath
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PINJECT_BUFFER pBuffer = NULL;
	SIZE_T size = PAGE_SIZE;
	HANDLE ProcessHandle;

	// Code
	UCHAR code[] =
	{
		0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
		0x48, 0x31, 0xC9,                       // xor rcx, rcx
		0x48, 0x31, 0xD2,                       // xor rdx, rdx
		0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r8, ModuleFileName   offset +12
		0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,     // mov r9, ModuleHandle     offset +28
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rax, LdrLoadDll      offset +32
		0xFF, 0xD0,                             // call rax
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, COMPLETE_OFFSET offset +44
		0xC7, 0x02, 0x7E, 0x1E, 0x37, 0xC0,     // mov [rdx], CALL_COMPLETE 
		0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,     // mov rdx, STATUS_OFFSET   offset +60
		0x89, 0x02,                             // mov [rdx], eax
		0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
		0xC3                                    // ret
	};

	status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &ProcessHandle);

	status = ZwAllocateVirtualMemory(ProcessHandle, &pBuffer, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, g_pNtdll, PAGE_SIZE);
	if (NT_SUCCESS(status) && pBuffer)
	{
		// Copy path
		PUNICODE_STRING pUserPath = &pBuffer->path;
		pUserPath->Length = 0;
		pUserPath->MaximumLength = sizeof(pBuffer->buffer);
		pUserPath->Buffer = pBuffer->buffer;

		RtlUnicodeStringCopy(pUserPath, pPath);

		// Copy code
		memcpy(pBuffer, code, sizeof(code));

		// Fill stubs
		*(ULONGLONG*)((PUCHAR)pBuffer + 12) = (ULONGLONG)pUserPath;
		*(ULONGLONG*)((PUCHAR)pBuffer + 22) = (ULONGLONG)&pBuffer->module;
		*(ULONGLONG*)((PUCHAR)pBuffer + 32) = (ULONGLONG)pLdrLoadDll;
		*(ULONGLONG*)((PUCHAR)pBuffer + 44) = (ULONGLONG)&pBuffer->complete;
		*(ULONGLONG*)((PUCHAR)pBuffer + 60) = (ULONGLONG)&pBuffer->status;

		return pBuffer;
	}

	if (ProcessHandle)
		ZwClose(ProcessHandle);

	return NULL;
}

NTSTATUS LookupSuitableThread(PEPROCESS Process, PETHREAD* pThread) {
	HANDLE pid;
	HANDLE currentTid;
	ULONG bytes;
	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_PROCESS_INFO pProcessInfo = NULL;
	PVOID pSavedProcessInfo = NULL;

	pid = PsGetProcessId(Process);
	currentTid = PsGetCurrentThreadId();
	__try {
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

		status = STATUS_NOT_FOUND;
		for (;;)
		{
			if (pProcessInfo->UniqueProcessId == pid)
			{
				status = STATUS_SUCCESS;
				break;
			}
			else if (pProcessInfo->NextEntryOffset)
				pProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
			else
				break;
		}

		if (!NT_SUCCESS(status))
			__leave;

		status = STATUS_NOT_FOUND;
		for (ULONG i = 0; i < pProcessInfo->NumberOfThreads; i++)
		{
			// Skip current thread
			if (pProcessInfo->Threads[i].WaitReason == Suspended ||
				pProcessInfo->Threads[i].ThreadState == 5 ||
				pProcessInfo->Threads[i].ClientId.UniqueThread == currentTid)
			{
				continue;
			}

			DbgBreakPoint();
			status = PsLookupThreadByThreadId(pProcessInfo->Threads[i].ClientId.UniqueThread, pThread);
			
			break;
		}

	}
	__finally {
		if (pSavedProcessInfo)
			ExFreePoolWithTag(pSavedProcessInfo, 'tag');
	}

	return status;
}

// Kernel routine for inject apc
VOID KernelApcInjectCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// Skip execution
	if (PsIsThreadTerminating(PsGetCurrentThread()))
		*NormalRoutine = NULL;

	// Fix Wow64 APC
	if (PsGetCurrentProcessWow64Process() != NULL)
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);

	ExFreePoolWithTag(Apc, 'tag');
}

// Kernel routine for prepare apc
VOID KernelApcPrepareCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	// Alert current thread
	KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, 'tag');
}