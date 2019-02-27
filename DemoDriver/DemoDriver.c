
#include "DemoDriver.h"

#include <ntstrsafe.h>
#include <ntimage.h>
#include "Internals.h"
#include "Inject.h"
#include "Callbacks.h"
#include "Misc.h"

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;
DRIVER_DISPATCH		DriverDispatch;
BOOLEAN CheckOsVersion();

PVOID pDriverObject = NULL;

#define DLL_PATH L"C:\\Users\\MOUKA\\Desktop\\TestDll.dll"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, DriverUnload)
#endif

VOID DriverTest() {
	// TEST

	//
	// Enum process APCs
	//
	//EnumProcessApc(L"winlogon.exe");

	//
	// Inject dll by APC
	//
	/*INJECT_INFO injectInfo = { 0 };
	injectInfo.Pid = 1640;
	RtlStringCbCopyW( injectInfo.Dllpath, MAX_PATH, DLL_PATH );

	InjectByApc( &injectInfo );*/

	// Enum CreateProcess/CreateThread/LoadImage notify routine
	TestInstallNotifyCallbacks();
	TestRegisterObCallbacks();
	TestRegisterCmCallbacks();
	TestRegistryEvents();
	//EnumCmCallbacks();
	//EnumObCallbacks();
	//DisableObCallback(ProcessObjectCallback);
	//DisableObCallback( ThreadObjectCallback );
	/*EnumNotifyCallbacks();
	GetNotifyMask();*/
	//DisableNotifyCallback(ProcessNotifyCallback);
	//DisableNotifyCallback(ThreadNotifyCallback);
	//DisableNotifyCallback(ImageNotifyCallback);
	//GetKernelBase2( NULL );

}

VOID DriverTestClean() {
	TestRemoveNotifyCallbacks();
	TestUnregisterObCallbacks();
	TestUnRegisterCmCallbacks();
}

NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING registryPath
)
{
	UNREFERENCED_PARAMETER( registryPath );

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceLink;

	if ( !CheckOsVersion() )	return STATUS_UNSUCCESSFUL;

	DriverObject->MajorFunction[IRP_MJ_CREATE] =
		DriverObject->MajorFunction[IRP_MJ_CLOSE] =
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
	DriverObject->DriverUnload = DriverUnload;

	DbgBreakPoint();
	RtlUnicodeStringInit( &deviceName, DEVICE_NAME );
	status = IoCreateDevice( DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject );
	if ( !NT_SUCCESS( status ) )
	{
		DbgPrint( "TEST: %s: IoCreateDevice failed with status 0x%X\n", __FUNCTION__, status );
		return status;
	}

	RtlUnicodeStringInit( &deviceLink, SYMBOLIC_NAME );
	status = IoCreateSymbolicLink( &deviceLink, &deviceName );
	if ( !NT_SUCCESS( status ) )
	{
		DbgPrint( "TEST: %s: IoCreateSymbolicLink failed with status 0x%X\n", __FUNCTION__, status );
		IoDeleteDevice( deviceObject );
		return status;
	}

	deviceObject->Flags |= DO_BUFFERED_IO;
	pDriverObject = DriverObject;

	DriverTest();

	return STATUS_SUCCESS;
}

BOOLEAN CheckOsVersion() {
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW osVersionLow = { 0 };
	RTL_OSVERSIONINFOEXW osVersionHigh = { 0 };
	ULONGLONG conditionMaskLow = 0;
	ULONGLONG conditionMaskHigh = 0;
	ULONG typeMask = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR;

	osVersionLow.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOEXW ); // Win Vista
	osVersionLow.dwMajorVersion = 6;
	osVersionLow.dwMinorVersion = 0;

	osVersionHigh.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOEXW ); // Win7
	osVersionHigh.dwMajorVersion = 6;
	osVersionHigh.dwMinorVersion = 1;

	VER_SET_CONDITION( conditionMaskLow, VER_MAJORVERSION, VER_GREATER_EQUAL );
	VER_SET_CONDITION( conditionMaskLow, VER_MINORVERSION, VER_GREATER_EQUAL );
	VER_SET_CONDITION( conditionMaskLow, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL );
	VER_SET_CONDITION( conditionMaskLow, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL );

	VER_SET_CONDITION( conditionMaskLow, VER_MAJORVERSION, VER_LESS_EQUAL );
	VER_SET_CONDITION( conditionMaskLow, VER_MINORVERSION, VER_LESS_EQUAL );
	VER_SET_CONDITION( conditionMaskLow, VER_SERVICEPACKMAJOR, VER_LESS_EQUAL );
	VER_SET_CONDITION( conditionMaskLow, VER_SERVICEPACKMINOR, VER_LESS_EQUAL );

	if ( RtlVerifyVersionInfo( &osVersionLow, typeMask, conditionMaskLow ) &&
		RtlVerifyVersionInfo( &osVersionHigh, typeMask, conditionMaskHigh ) ) {
		DbgBreakPoint();
		return TRUE;
	}

	return FALSE;

}

VOID DriverUnload( PDRIVER_OBJECT DriverObject ) {
	/*UNREFERENCED_PARAMETER(DriverObject);*/
	UNICODE_STRING	deviceSymLink;
	PAGED_CODE();
	DbgBreakPoint();
	DriverTestClean();

	RtlUnicodeStringInit( &deviceSymLink, SYMBOLIC_NAME );
	IoDeleteSymbolicLink( &deviceSymLink );
	IoDeleteDevice( DriverObject->DeviceObject );

}

NTSTATUS DriverDispatch( PDEVICE_OBJECT DeviceObject, PIRP Irp ) {
	UNREFERENCED_PARAMETER( DeviceObject );

	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	PVOID ioBuffer = NULL;
	ULONG inputBufferLength = 0;
	ULONG outputBufferLength = 0;
	ULONG ioControlCode = 0;

	irpStack = IoGetCurrentIrpStackLocation( Irp );
	ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;


	if ( irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL ) {
		switch ( ioControlCode )
		{
			case IOCTL_ENUM_PROCESS_APC:
				if ( inputBufferLength <= MAX_PATH ) {
					status = EnumProcessApc( (PCWSTR)ioBuffer );
				}
				else {
					status = STATUS_INVALID_PARAMETER;
				}
				break;

			case IOCTL_INJECT_DLL:
				if ( inputBufferLength == sizeof( INJECT_INFO ) ) {
					status = InjectDll( (PINJECT_INFO)ioBuffer );
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
	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return status;
}


