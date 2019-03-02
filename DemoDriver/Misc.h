#pragma once

#include <ntifs.h>

#define OFFSET_DPC_DATA 0x2180

//
// Get ntos kernel base
//
PVOID GetKernelBase2( PULONG NtosSize );

//
// Enum process APCs
//
NTSTATUS EnumProcessApc( PCWSTR ProcessName );
NTSTATUS EnumThreadApc( PETHREAD Thread );

//
// Enum all DPCs in the system
//
VOID EnumAllDpcs();
VOID EnumProcessorDpcs(PVOID pKRCB);
VOID TestSetDpcs();
VOID TestRemoveDpcs();

