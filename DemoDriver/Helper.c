#include <ntifs.h>
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

	RtlInitUnicodeString(&uProcessName, ProcessName);

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