
#include "driver.h"


BOOLEAN IsStringTerminated(PCHAR pString, UINT uiLength);

_Use_decl_annotations_
NTSTATUS ExampleCreate(
	PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	KdPrint(("ExampleCreate Called.\n"));
	return STATUS_SUCCESS;
}

NTSTATUS ExampleClose(
	
	PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("ExampleClose Called.\n");
	return STATUS_SUCCESS;
}

NTSTATUS ExampleRead(
	PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	NTSTATUS NtStatus = STATUS_SUCCESS;
	KdPrint(("Example_Read Called \r\n"));

	return NtStatus;
}

//NTSTATUS ExampleUnsupportedFunction(
//	
//	)
//{
//	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
//	DbgPrint("Example_UnSupportedFunction Called \r\n");
//
//	return NtStatus;
//}