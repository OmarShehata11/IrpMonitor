/*++

Module Name:

    IrpMonitor.c

Abstract:

    This is the main module of the IrpMonitor miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include "MainHeader.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, IrpMonitorUnload)
#pragma alloc_text(PAGE, IrpMonitorInstanceQueryTeardown)
#pragma alloc_text(PAGE, IrpMonitorInstanceSetup)
#pragma alloc_text(PAGE, IrpMonitorInstanceTeardownStart)
#pragma alloc_text(PAGE, IrpMonitorInstanceTeardownComplete)
#endif

//
//  operation registration
//

// I'm going to monitor all possible IRPs

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {


    { IRP_MJ_CREATE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_CLOSE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_READ,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_WRITE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_QUERY_EA,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_SET_EA,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_SHUTDOWN,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_CLEANUP,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_QUERY_SECURITY,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_SET_SECURITY,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_QUERY_QUOTA,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_SET_QUOTA,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_PNP,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_MDL_READ,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      IrpMonitorPreOperationNoPostOperation,
      NULL },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    IrpMonitorUnload,                           //  MiniFilterUnload

    NULL,                                //  InstanceSetup
    NULL,                                //  InstanceQueryTeardown
    NULL,                                //  InstanceTeardownStart
    NULL,                                //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
IrpMonitorInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    DBG_PRINT( DBG_TRACE_ROUTINES,
                  ("IrpMonitor!IrpMonitorInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
IrpMonitorInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DBG_PRINT( DBG_TRACE_ROUTINES,
                  ("IrpMonitor!IrpMonitorInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
IrpMonitorInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DBG_PRINT( DBG_TRACE_ROUTINES,
                  ("IrpMonitor!IrpMonitorInstanceTeardownStart: Entered\n") );
}


VOID
IrpMonitorInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DBG_PRINT( DBG_TRACE_ROUTINES,
                  ("IrpMonitor!IrpMonitorInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    DBG_PRINT( DBG_TRACE_ROUTINES,
                  ("IrpMonitor!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
IrpMonitorUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DBG_PRINT( DBG_TRACE_ROUTINES,
                  ("IrpMonitor!IrpMonitorUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/


FLT_PREOP_CALLBACK_STATUS
IrpMonitorPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;
    BOOLEAN IsTargetProcess = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

   // DBG_PRINT(DBG_TRACE_ROUTINES,
   //     ("IrpMonitor!IrpMonitorPreOperation: Entered\n"));

    // skip if from kernel space
    if(Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // check the process Name:
    status = IrpMonitorCheckTargetProcess(Data, FltObjects, &IsTargetProcess);

    if (NT_SUCCESS(status) && IsTargetProcess)
    {
        UCHAR majorFunction = Data->Iopb->MajorFunction;

        switch (majorFunction)
        {
        case IRP_MJ_CREATE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_CREATE)\n"));

            IrpMonitorCreateIRPDescriptor(Data->Iopb->Parameters.Create.Options,
                Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess);

            break;

        case IRP_MJ_CLOSE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_CLOSE)\n"));
            break;

        case IRP_MJ_READ:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_READ)\n"));
            break;

        case IRP_MJ_WRITE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_WRITE)\n"));
            break;

        case IRP_MJ_QUERY_INFORMATION:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_QUERY_INFORMATION)\n"));

            IrpMonitorFileInformationIRPDescriptor(Data->Iopb->Parameters.QueryFileInformation.FileInformationClass);

            break;

        case IRP_MJ_SET_INFORMATION:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_SET_INFORMATION)\n"));

            IrpMonitorFileInformationIRPDescriptor(Data->Iopb->Parameters.SetFileInformation.FileInformationClass);

            break;

        case IRP_MJ_FLUSH_BUFFERS:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_FLUSH_BUFFERS)\n"));
            break;

        case IRP_MJ_SHUTDOWN:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_SHUTDOWN)\n"));
            break;

        case IRP_MJ_DEVICE_CONTROL:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_DEVICE_CONTROL)\n"));
            break;

        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_INTERNAL_DEVICE_CONTROL)\n"));
            break;

        case IRP_MJ_DIRECTORY_CONTROL:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_DIRECTORY_CONTROL)\n"));

            IrpMonitorFileInformationIRPDescriptor(Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass);

            DBG_PRINT(DBG_MESSAGES_TO_USER, ("Directory Name : %wZ\n",
                Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName));

            break;

        case IRP_MJ_LOCK_CONTROL:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_LOCK_CONTROL)\n"));
            break;

        case IRP_MJ_CLEANUP:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_CLEANUP)\n"));
            break;

        case IRP_MJ_CREATE_NAMED_PIPE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_CREATE_NAMED_PIPE)\n"));
            break;

        case IRP_MJ_FILE_SYSTEM_CONTROL:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_FILE_SYSTEM_CONTROL)\n"));
            break;

        case IRP_MJ_QUERY_SECURITY:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_QUERY_SECURITY)\n"));
            break;

        case IRP_MJ_SET_SECURITY:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_SET_SECURITY)\n"));
            break;

        case IRP_MJ_QUERY_VOLUME_INFORMATION:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_QUERY_VOLUME_INFORMATION)\n"));
            break;

        case IRP_MJ_SET_VOLUME_INFORMATION:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_SET_VOLUME_INFORMATION)\n"));
            break;

        case IRP_MJ_PNP:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_PNP)\n"));
            break;

        case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION)\n"));
            break;

        case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION)\n"));
            break;

        case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_ACQUIRE_FOR_MOD_WRITE)\n"));
            break;

        case IRP_MJ_RELEASE_FOR_MOD_WRITE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_RELEASE_FOR_MOD_WRITE)\n"));
            break;

        case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_ACQUIRE_FOR_CC_FLUSH)\n"));
            break;

        case IRP_MJ_RELEASE_FOR_CC_FLUSH:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_RELEASE_FOR_CC_FLUSH)\n"));
            break;

        case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE)\n"));
            break;

        case IRP_MJ_NETWORK_QUERY_OPEN:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_NETWORK_QUERY_OPEN)\n"));
            break;

        case IRP_MJ_MDL_READ:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_MDL_READ)\n"));
            break;

        case IRP_MJ_MDL_READ_COMPLETE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_MDL_READ_COMPLETE)\n"));
            break;

        case IRP_MJ_PREPARE_MDL_WRITE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_PREPARE_MDL_WRITE)\n"));
            break;

        case IRP_MJ_MDL_WRITE_COMPLETE:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_MDL_WRITE_COMPLETE)\n"));
            break;

        case IRP_MJ_VOLUME_MOUNT:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_VOLUME_MOUNT)\n"));
            break;

        case IRP_MJ_VOLUME_DISMOUNT:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (IRP_MJ_VOLUME_DISMOUNT)\n"));
            break;

        default:
            DBG_PRINT(DBG_MESSAGES_TO_USER, ("[+] Catched an (UNKNOWN IRP: %d)\n", majorFunction));
            break;
        }

        DBG_PRINT(DBG_MESSAGES_TO_USER, ("============================================\n"));
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS IrpMonitorCheckTargetProcess(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PBOOLEAN IsTargetProcess
)
{
    PUNICODE_STRING ProcessPath = NULL;
    ULONG PoolSize = 300;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess;
    PEPROCESS pEPROCESS;

    UNREFERENCED_PARAMETER(FltObjects);

    ProcessPath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_PAGED, PoolSize, '1gaT');

    if (ProcessPath == NULL)
    {
        DBG_PRINT(DBG_TRACE_OPERATION_STATUS,
            ("[-] ERROR: Couldn't allocate space for process Name.\n"));

        goto CLEANUP;
    }

    RtlZeroMemory(ProcessPath, PoolSize);

    status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, ProcessPath,
        PoolSize - sizeof(WCHAR), NULL);

    if (!NT_SUCCESS(status))
    {
        // Now try the other method
        pEPROCESS = PsGetThreadProcess(Data->Thread);

        status = ObOpenObjectByPointer(pEPROCESS, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hProcess);

        if (!NT_SUCCESS(status))
        {
            DBG_PRINT(DBG_TRACE_OPERATION_STATUS, ("[-] ERROR: Couldn't open a handle to the process.\n"));
            goto CLEANUP;
        }


        status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, ProcessPath,
            PoolSize - sizeof(WCHAR), NULL);

        if (!NT_SUCCESS(status))
        {
            DBG_PRINT(DBG_TRACE_OPERATION_STATUS,
                ("[-] ERROR: Couldn't get the name of the file using the second method.\n"));


            goto CLEANUP;
        }

    }

    // Now we have the process Name, Let's do the comparisson:

    // assuming that both buffers are null-terminated (I should fix that code and use another function)
    if (wcsstr(ProcessPath->Buffer, L"IrpMonitorHelper.exe")) 
        *IsTargetProcess = TRUE;

    else
        *IsTargetProcess = FALSE;
    

CLEANUP:
    if (ProcessPath != NULL)
        ExFreePoolWithTag(ProcessPath, '1gaT');

    return status;
}


VOID IrpMonitorCreateIRPDescriptor(
    ULONG options,
    ULONG DesiredAccess
)
{
    // LOW 24 BITS (CreateOptions)
    ULONG opt = options & 0xffffff; 

    // high 8 bits (CreateDisposition)
    options = options >> 24;

    KdPrint(("[IRP_MONITOR]: THE CREATE OPTIONS FOR THE CREATE REQUEST IS 0x%X: \n", opt));

    if (IRPM_FlagOn(opt, FILE_DIRECTORY_FILE)) {
        KdPrint(("  - FILE_DIRECTORY_FILE\n"));
    }
    if (IRPM_FlagOn(opt, FILE_WRITE_THROUGH)) {
        KdPrint(("  - FILE_WRITE_THROUGH\n"));
    }
    if (IRPM_FlagOn(opt, FILE_SEQUENTIAL_ONLY)) {
        KdPrint(("  - FILE_SEQUENTIAL_ONLY\n"));
    }
    if (IRPM_FlagOn(opt, FILE_NO_INTERMEDIATE_BUFFERING)) {
        KdPrint(("  - FILE_NO_INTERMEDIATE_BUFFERING\n"));
    }
    if (IRPM_FlagOn(opt, FILE_SYNCHRONOUS_IO_ALERT)) {
        KdPrint(("  - FILE_SYNCHRONOUS_IO_ALERT\n"));
    }
    if (IRPM_FlagOn(opt, FILE_SYNCHRONOUS_IO_NONALERT)) {
        KdPrint(("  - FILE_SYNCHRONOUS_IO_NONALERT\n"));
    }
    if (IRPM_FlagOn(opt, FILE_NON_DIRECTORY_FILE)) {
        KdPrint(("  - FILE_NON_DIRECTORY_FILE\n"));
    }
    if (IRPM_FlagOn(opt, FILE_CREATE_TREE_CONNECTION)) {
        KdPrint(("  - FILE_CREATE_TREE_CONNECTION\n"));
    }
    if (IRPM_FlagOn(opt, FILE_COMPLETE_IF_OPLOCKED)) {
        KdPrint(("  - FILE_COMPLETE_IF_OPLOCKED\n"));
    }
    if (IRPM_FlagOn(opt, FILE_NO_EA_KNOWLEDGE)) {
        KdPrint(("  - FILE_NO_EA_KNOWLEDGE\n"));
    }
    if (IRPM_FlagOn(opt, FILE_OPEN_REMOTE_INSTANCE)) {
        KdPrint(("  - FILE_OPEN_REMOTE_INSTANCE\n"));
    }
    if (IRPM_FlagOn(opt, FILE_RANDOM_ACCESS)) {
        KdPrint(("  - FILE_RANDOM_ACCESS\n"));
    }
    if (IRPM_FlagOn(opt, FILE_DELETE_ON_CLOSE)) {
        KdPrint(("  - FILE_DELETE_ON_CLOSE\n"));
    }
    if (IRPM_FlagOn(opt, FILE_OPEN_BY_FILE_ID)) {
        KdPrint(("  - FILE_OPEN_BY_FILE_ID\n"));
    }
    if (IRPM_FlagOn(opt, FILE_OPEN_FOR_BACKUP_INTENT)) {
        KdPrint(("  - FILE_OPEN_FOR_BACKUP_INTENT\n"));
    }
    if (IRPM_FlagOn(opt, FILE_NO_COMPRESSION)) {
        KdPrint(("  - FILE_NO_COMPRESSION\n"));
    }
    if (IRPM_FlagOn(opt, FILE_RESERVE_OPFILTER)) {
        KdPrint(("  - FILE_RESERVE_OPFILTER\n"));
    }
    if (IRPM_FlagOn(opt, FILE_OPEN_REPARSE_POINT)) {
        KdPrint(("  - FILE_OPEN_REPARSE_POINT\n"));
    }
    if (IRPM_FlagOn(opt, FILE_OPEN_NO_RECALL)) {
        KdPrint(("  - FILE_OPEN_NO_RECALL\n"));
    }
    if (IRPM_FlagOn(opt, FILE_OPEN_FOR_FREE_SPACE_QUERY)) {
        KdPrint(("  - FILE_OPEN_FOR_FREE_SPACE_QUERY\n"));
    }


    KdPrint(("[IRP_MONITOR]: THE CREATE DISPOSITION FOR THE CREATE REQUEST IS 0x%X: \n", options));
    if (IRPM_FlagOn(options, FILE_SUPERSEDE))
        KdPrint((" - FILE_SUPERSEDE\n"));

    if (IRPM_FlagOn(options, FILE_CREATE))
        KdPrint((" - FILE_CREATE\n"));

    if (IRPM_FlagOn(options, FILE_OPEN))
        KdPrint((" - FILE_OPEN\n"));

    if (IRPM_FlagOn(options, FILE_OPEN_IF))
        KdPrint((" - FILE_OPEN_IF\n"));

    if (IRPM_FlagOn(options, FILE_OVERWRITE))
        KdPrint((" - FILE_OVERWRITE\n"));

    if (IRPM_FlagOn(options, FILE_OVERWRITE_IF))
        KdPrint((" - FILE_OVERWRITE_IF\n"));

    // 
    // NOW THE DESIRED ACCESS..
    //

    KdPrint(("[IRP_MONITOR]: THE DESIRED ACCESS FOR THE CREATE REQUEST IS: 0x%X\n", DesiredAccess));

    if (IRPM_FlagOn(DesiredAccess, FILE_READ_DATA)) {
        KdPrint(("  - FILE_READ_DATA\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_WRITE_DATA)) {
        KdPrint(("  - FILE_WRITE_DATA\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_APPEND_DATA)) {
        KdPrint(("  - FILE_APPEND_DATA\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_READ_EA)) {
        KdPrint(("  - FILE_READ_EA\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_WRITE_EA)) {
        KdPrint(("  - FILE_WRITE_EA\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_EXECUTE)) {
        KdPrint(("  - FILE_EXECUTE\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_DELETE_CHILD)) {
        KdPrint(("  - FILE_DELETE_CHILD\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_READ_ATTRIBUTES)) {
        KdPrint(("  - FILE_READ_ATTRIBUTES\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, FILE_WRITE_ATTRIBUTES)) {
        KdPrint(("  - FILE_WRITE_ATTRIBUTES\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, DELETE)) {
        KdPrint(("  - DELETE\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, READ_CONTROL)) {
        KdPrint(("  - READ_CONTROL\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, WRITE_DAC)) {
        KdPrint(("  - WRITE_DAC\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, WRITE_OWNER)) {
        KdPrint(("  - WRITE_OWNER\n"));
    }
    if (IRPM_FlagOn(DesiredAccess, SYNCHRONIZE)) {
        KdPrint(("  - SYNCHRONIZE\n"));
    }
}


VOID IrpMonitorFileInformationIRPDescriptor(
    FILE_INFORMATION_CLASS fileInfoClass
)
{
    KdPrint(("[IRP_MONITOR]: THE FILE INFORMATION CLASS FOR THE REQUEST IS: %d\n", fileInfoClass));

    switch (fileInfoClass) {
    case FileDirectoryInformation:
        KdPrint(("  - FileDirectoryInformation\n"));
        break;
    case FileFullDirectoryInformation:
        KdPrint(("  - FileFullDirectoryInformation\n"));
        break;
    case FileBothDirectoryInformation:
        KdPrint(("  - FileBothDirectoryInformation\n"));
        break;
    case FileBasicInformation:
        KdPrint(("  - FileBasicInformation\n"));
        break;
    case FileStandardInformation:
        KdPrint(("  - FileStandardInformation\n"));
        break;
    case FileInternalInformation:
        KdPrint(("  - FileInternalInformation\n"));
        break;
    case FileEaInformation:
        KdPrint(("  - FileEaInformation\n"));
        break;
    case FileAccessInformation:
        KdPrint(("  - FileAccessInformation\n"));
        break;
    case FileNameInformation:
        KdPrint(("  - FileNameInformation\n"));
        break;
    case FileRenameInformation:
        KdPrint(("  - FileRenameInformation\n"));
        break;
    case FileLinkInformation:
        KdPrint(("  - FileLinkInformation\n"));
        break;
    case FileNamesInformation:
        KdPrint(("  - FileNamesInformation\n"));
        break;
    case FileDispositionInformation:
        KdPrint(("  - FileDispositionInformation\n"));
        break;
    case FilePositionInformation:
        KdPrint(("  - FilePositionInformation\n"));
        break;
    case FileFullEaInformation:
        KdPrint(("  - FileFullEaInformation\n"));
        break;
    case FileModeInformation:
        KdPrint(("  - FileModeInformation\n"));
        break;
    case FileAlignmentInformation:
        KdPrint(("  - FileAlignmentInformation\n"));
        break;
    case FileAllInformation:
        KdPrint(("  - FileAllInformation\n"));
        break;
    case FileAllocationInformation:
        KdPrint(("  - FileAllocationInformation\n"));
        break;
    case FileEndOfFileInformation:
        KdPrint(("  - FileEndOfFileInformation\n"));
        break;
    case FileAlternateNameInformation:
        KdPrint(("  - FileAlternateNameInformation\n"));
        break;
    case FileStreamInformation:
        KdPrint(("  - FileStreamInformation\n"));
        break;
    case FilePipeInformation:
        KdPrint(("  - FilePipeInformation\n"));
        break;
    case FilePipeLocalInformation:
        KdPrint(("  - FilePipeLocalInformation\n"));
        break;
    case FilePipeRemoteInformation:
        KdPrint(("  - FilePipeRemoteInformation\n"));
        break;
    case FileMailslotQueryInformation:
        KdPrint(("  - FileMailslotQueryInformation\n"));
        break;
    case FileMailslotSetInformation:
        KdPrint(("  - FileMailslotSetInformation\n"));
        break;
    case FileCompressionInformation:
        KdPrint(("  - FileCompressionInformation\n"));
        break;
    case FileObjectIdInformation:
        KdPrint(("  - FileObjectIdInformation\n"));
        break;
    case FileCompletionInformation:
        KdPrint(("  - FileCompletionInformation\n"));
        break;
    case FileMoveClusterInformation:
        KdPrint(("  - FileMoveClusterInformation\n"));
        break;
    case FileQuotaInformation:
        KdPrint(("  - FileQuotaInformation\n"));
        break;
    case FileReparsePointInformation:
        KdPrint(("  - FileReparsePointInformation\n"));
        break;
    case FileNetworkOpenInformation:
        KdPrint(("  - FileNetworkOpenInformation\n"));
        break;
    case FileAttributeTagInformation:
        KdPrint(("  - FileAttributeTagInformation\n"));
        break;
    case FileTrackingInformation:
        KdPrint(("  - FileTrackingInformation\n"));
        break;
    case FileIdBothDirectoryInformation:
        KdPrint(("  - FileIdBothDirectoryInformation\n"));
        break;
    case FileIdFullDirectoryInformation:
        KdPrint(("  - FileIdFullDirectoryInformation\n"));
        break;
    case FileValidDataLengthInformation:
        KdPrint(("  - FileValidDataLengthInformation\n"));
        break;
    case FileShortNameInformation:
        KdPrint(("  - FileShortNameInformation\n"));
        break;
    case FileIoCompletionNotificationInformation:
        KdPrint(("  - FileIoCompletionNotificationInformation\n"));
        break;
    case FileIoStatusBlockRangeInformation:
        KdPrint(("  - FileIoStatusBlockRangeInformation\n"));
        break;
    case FileIoPriorityHintInformation:
        KdPrint(("  - FileIoPriorityHintInformation\n"));
        break;
    case FileSfioReserveInformation:
        KdPrint(("  - FileSfioReserveInformation\n"));
        break;
    case FileSfioVolumeInformation:
        KdPrint(("  - FileSfioVolumeInformation\n"));
        break;
    case FileHardLinkInformation:
        KdPrint(("  - FileHardLinkInformation\n"));
        break;
    case FileProcessIdsUsingFileInformation:
        KdPrint(("  - FileProcessIdsUsingFileInformation\n"));
        break;
    case FileNormalizedNameInformation:
        KdPrint(("  - FileNormalizedNameInformation\n"));
        break;
    case FileNetworkPhysicalNameInformation:
        KdPrint(("  - FileNetworkPhysicalNameInformation\n"));
        break;
    case FileIdGlobalTxDirectoryInformation:
        KdPrint(("  - FileIdGlobalTxDirectoryInformation\n"));
        break;
    case FileIsRemoteDeviceInformation:
        KdPrint(("  - FileIsRemoteDeviceInformation\n"));
        break;
    case FileUnusedInformation:
        KdPrint(("  - FileUnusedInformation\n"));
        break;
    case FileNumaNodeInformation:
        KdPrint(("  - FileNumaNodeInformation\n"));
        break;
    case FileStandardLinkInformation:
        KdPrint(("  - FileStandardLinkInformation\n"));
        break;
    case FileRemoteProtocolInformation:
        KdPrint(("  - FileRemoteProtocolInformation\n"));
        break;
    case FileRenameInformationBypassAccessCheck:
        KdPrint(("  - FileRenameInformationBypassAccessCheck\n"));
        break;
    case FileLinkInformationBypassAccessCheck:
        KdPrint(("  - FileLinkInformationBypassAccessCheck\n"));
        break;
    case FileVolumeNameInformation:
        KdPrint(("  - FileVolumeNameInformation\n"));
        break;
    case FileIdInformation:
        KdPrint(("  - FileIdInformation\n"));
        break;
    case FileIdExtdDirectoryInformation:
        KdPrint(("  - FileIdExtdDirectoryInformation\n"));
        break;
    case FileReplaceCompletionInformation:
        KdPrint(("  - FileReplaceCompletionInformation\n"));
        break;
    case FileHardLinkFullIdInformation:
        KdPrint(("  - FileHardLinkFullIdInformation\n"));
        break;
    case FileIdExtdBothDirectoryInformation:
        KdPrint(("  - FileIdExtdBothDirectoryInformation\n"));
        break;
    case FileDispositionInformationEx:
        KdPrint(("  - FileDispositionInformationEx\n"));
        break;
    case FileRenameInformationEx:
        KdPrint(("  - FileRenameInformationEx\n"));
        break;
    case FileRenameInformationExBypassAccessCheck:
        KdPrint(("  - FileRenameInformationExBypassAccessCheck\n"));
        break;
    case FileDesiredStorageClassInformation:
        KdPrint(("  - FileDesiredStorageClassInformation\n"));
        break;
    case FileStatInformation:
        KdPrint(("  - FileStatInformation\n"));
        break;
    case FileMemoryPartitionInformation:
        KdPrint(("  - FileMemoryPartitionInformation\n"));
        break;
    case FileStatLxInformation:
        KdPrint(("  - FileStatLxInformation\n"));
        break;
    case FileCaseSensitiveInformation:
        KdPrint(("  - FileCaseSensitiveInformation\n"));
        break;
    case FileLinkInformationEx:
        KdPrint(("  - FileLinkInformationEx\n"));
        break;
    case FileLinkInformationExBypassAccessCheck:
        KdPrint(("  - FileLinkInformationExBypassAccessCheck\n"));
        break;
    case FileStorageReserveIdInformation:
        KdPrint(("  - FileStorageReserveIdInformation\n"));
        break;
    case FileCaseSensitiveInformationForceAccessCheck:
        KdPrint(("  - FileCaseSensitiveInformationForceAccessCheck\n"));
        break;
    case FileMaximumInformation:
        KdPrint(("  - FileMaximumInformation\n"));
        break;
    default:
        KdPrint(("  - Unknown FileInformationClass (%d)\n", fileInfoClass));
        break;
    }
}

NTSTATUS IrpRtlCompareStringsWcsstr(
    IN PUNICODE_STRING Str,
    IN PUNICODE_STRING StrSearch,
    OUT PBOOLEAN IsSuccess
)
{
    if (!Str || !StrSearch || !IsSuccess)
        return STATUS_INVALID_PARAMETER;

    if (Str->Length <= StrSearch->Length)
        return STATUS_UNSUCCESSFUL;


    USHORT counter;

    for (counter = 0; counter < StrSearch->Length; counter++)
    {
        if (RtlCompareMemory(Str->Buffer[counter], StrSearch->Buffer, StrSearch->Length) == StrSearch->Length)
        {
            *IsSuccess = TRUE;
            return
        }
    }


}