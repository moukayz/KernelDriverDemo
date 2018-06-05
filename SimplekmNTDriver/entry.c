#include "driver.h"

VOID ExampleUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);


#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ExampleUnload)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	UINT uiIndex = 0;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING usDeviceName, usDosDeviceName;
	PDRIVER_DISPATCH dispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1];

	DbgPrint("DriverEntry Called.\n");

	RtlInitUnicodeString(&usDeviceName, L"\\Device\\Example");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Example");

	status = IoCreateDevice(DriverObject,
		0,
		&usDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&deviceObject);

	if (status == STATUS_SUCCESS)
	{
		for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
		{
			//DriverObject->MajorFunction[uiIndex] = ExampleUnsupportedFunction;

		}

		/*DriverObject->MajorFunction[IRP_MJ_CLOSE] = ExampleClose;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = ExampleCreate;
		DriverObject->MajorFunction[IRP_MJ_READ] = ExampleRead;*/

		dispatchTable[IRP_MJ_CLOSE] = ExampleClose;
		dispatchTable[IRP_MJ_CREATE] = ExampleCreate;
		dispatchTable[IRP_MJ_READ] = ExampleRead;


		DriverObject->DriverUnload = ExampleUnload;

		deviceObject->Flags |= IO_TYPE;
		deviceObject->Flags &= (DO_DEVICE_INITIALIZING);

		IoCreateSymbolicLink(&usDosDeviceName, &usDeviceName);
	}

	return status;
}

VOID ExampleUnload(PDRIVER_OBJECT  DriverObject)
{

	UNICODE_STRING usDosDeviceName;

	DbgPrint("Example_Unload Called \r\n");

	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\Example");
	IoDeleteSymbolicLink(&usDosDeviceName);

	IoDeleteDevice(DriverObject->DeviceObject);
}