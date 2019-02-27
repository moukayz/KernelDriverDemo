#pragma once

#include <ntifs.h>

//
// Get ntos kernel base
//
PVOID GetKernelBase2( PULONG NtosSize );

//
// Enum process APCs
//
NTSTATUS EnumProcessApc( PCWSTR ProcessName );
NTSTATUS EnumThreadApc( PETHREAD Thread );

