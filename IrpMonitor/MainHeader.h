#pragma once
#include <fltKernel.h>

#define IRPM_FlagOn(_x, _y) (BOOLEAN)(((_x) & (_y)) == (_y))


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define DBG_TRACE_ROUTINES            0x00000001
#define DBG_TRACE_OPERATION_STATUS    0x00000002
#define DBG_MESSAGES_TO_USER    0x00000004



// Self added code, to just make the debug prints the the INFO and ERROR type of messages.
#define DEBUG_ERROR  0x01
#define DEBUG_INFO   0x02
#define DEBUG_MESSAGE 0x04

ULONG gTraceFlags = DEBUG_ERROR | DEBUG_INFO | DEBUG_MESSAGE;

// log the files only if the gTraceFlags flag is enabled.
#define DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0)) 



/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

NTSTATUS ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS IrpMonitorCheckTargetProcess(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PBOOLEAN IsTargetProcess
);

VOID IrpMonitorCreateIRPDescriptor(
    ULONG options,
    ULONG DesiredAccess
);

VOID IrpMonitorFileInformationIRPDescriptor(
    FILE_INFORMATION_CLASS fileInfoClass
);

NTSTATUS IrpRtlCompareStringsWcsstr(
    IN PUNICODE_STRING Str,
    IN PUNICODE_STRING StrSearch,
    OUT PBOOLEAN IsSuccess
);

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
IrpMonitorInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
IrpMonitorInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
IrpMonitorInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
IrpMonitorUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
IrpMonitorInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID
IrpMonitorOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);


FLT_PREOP_CALLBACK_STATUS
IrpMonitorPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
IrpMonitorDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);

EXTERN_C_END