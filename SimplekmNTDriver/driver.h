#include <ntddk.h>
#include <wdm.h>

#ifndef __DRIVER_H__
#define __DRIVER_H__

typedef unsigned int UINT;
typedef char* PCHAR;

_Use_decl_annotations_ NTSTATUS ExampleCreate(PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp);
NTSTATUS ExampleClose(PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp);
NTSTATUS ExampleRead(PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp);
NTSTATUS ExampleUnsupportedFunction(PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp);

#ifndef IO_TYPE
#define IO_TYPE 0
#define USE_WRITE_FUNCTION ExampleWriteNeither
#endif

#endif

