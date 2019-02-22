#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "DemoDriver.h"
#include "Internals.h"

NTSTATUS GetProcessIdByName(IN PWSTR ProcessName, OUT PULONG Pid) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	UNICODE_STRING uProcessName;
	PSYSTEM_PROCESS_INFO pProcessInfo = NULL;
	
	if (ProcessName == NULL || Pid == NULL)	return STATUS_INVALID_PARAMETER;
	// Get the process thread list
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	pProcessInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, bytes, 'tag');
	RtlZeroMemory(pProcessInfo, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pProcessInfo, bytes, &bytes);
	if (NT_SUCCESS(status))	return status;

	RtlUnicodeStringInit(&uProcessName, ProcessName);

	for (;;) {
		if (FsRtlIsNameInExpression(&uProcessName, &pProcessInfo->ImageName, TRUE, NULL)) {
			*Pid = pProcessInfo->UniqueProcessId;
			break;
		}

		if (pProcessInfo->NextEntryOffset)
			pProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pProcessInfo + pProcessInfo->NextEntryOffset);
		else {
			*Pid = 0;
			break;
		}
	}

	if (*Pid)
		return STATUS_SUCCESS;
		
	return STATUS_NOT_FOUND;
}

BOOLEAN CheckProcessTermination(PEPROCESS pProcess)
{
	LARGE_INTEGER zeroTime = { 0 };
	return KeWaitForSingleObject(pProcess, Executive, KernelMode, FALSE, &zeroTime) == STATUS_WAIT_0;
}

PVOID GetUserModule(
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING ModuleName,
	IN BOOLEAN isWow64
)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		LARGE_INTEGER time = { 0 };
		time.QuadPart = -250ll * 10 * 1000;     // 250 msec.

												// Wow64 process
		if (isWow64)
		{
			PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
			if (pPeb32 == NULL)
			{
				DbgPrint("TEST: %s: No PEB present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Wait for loader a bit
			for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
			{
				DbgPrint("TEST: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb32->Ldr)
			{
				DbgPrint("TEST: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
				pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
				pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
			{
				UNICODE_STRING ustr;
				PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

				RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

				if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
					return (PVOID)pEntry->DllBase;
			}
		}
		// Native process
		else
		{
			PPEB pPeb = PsGetProcessPeb(pProcess);
			if (!pPeb)
			{
				DbgPrint("TEST: %s: No PEB present. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Wait for loader a bit
			for (INT i = 0; !pPeb->Ldr && i < 10; i++)
			{
				DbgPrint("TEST: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
				KeDelayExecutionThread(KernelMode, TRUE, &time);
			}

			// Still no loader
			if (!pPeb->Ldr)
			{
				DbgPrint("TEST: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
				return NULL;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
				pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
				pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
					return pEntry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("TEST: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	return NULL;
}

PVOID GetModuleExport(
	IN PVOID pBase,
	IN PCCHAR name_ord,
	IN PEPROCESS pProcess,
	IN PUNICODE_STRING baseName
)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;

	ASSERT(pBase != NULL);

	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		// Not a PE file
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		// Not a PE file
		return NULL;

	// If 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	PULONG	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	ANSI_STRING strSrcFunc = { 0 };
	ANSI_STRING strCurFunc = { 0 };
	RtlInitAnsiString(&strSrcFunc, name_ord);

	for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		if ((ULONG_PTR)name_ord < 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			RtlInitAnsiString(&strCurFunc, pName);
			OrdIndex = pAddressOfOrds[i];
		}
		else
			return NULL;

		if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
			((ULONG_PTR)name_ord > 0xFFFF && RtlCompareString(&strSrcFunc, &strCurFunc, TRUE) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
			break;

		}
	}

	return (PVOID)pAddress;
}