#include <fltKernel.h>

#include <s2e.h>
#include <WindowsMonitor2.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

typedef struct _SCANNER_DATA {
    /**
     * The filter handle that results from a call to
     * FltRegisterFilter.
     */
    PFLT_FILTER Filter;
} SCANNER_DATA, *PSCANNER_DATA;

/**
 * Structure that contains all the global data structures
 * used throughout the scanner.
 */
SCANNER_DATA ScannerData = {0};

/* Function prototypes */

NTSTATUS RegisterFilesystemFilter (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
);

NTSTATUS ScannerInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS ScannerQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS UnregisterFilesystemFilter (__in FLT_FILTER_UNLOAD_FLAGS Flags);

/* Assign text sections for each routine. */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, RegisterFilesystemFilter)
#pragma alloc_text(PAGE, ScannerInstanceSetup)
#pragma alloc_text(PAGE, ScannerPostCreate)
#endif


//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, ScannerPostCreate},
    { IRP_MJ_OPERATION_END}
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    UnregisterFilesystemFilter,         //  FilterUnload
    ScannerInstanceSetup,               //  InstanceSetup
    ScannerQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS RegisterFilesystemFilter (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd;
    NTSTATUS status;
    UNICODE_STRING ntDeviceName;
    UNICODE_STRING win32DeviceName;
    PDEVICE_OBJECT deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    S2EMessageFmt("lfidriver: registering filesystem filter");

    /* Register with filter manager. */
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &ScannerData.Filter);

    if (!NT_SUCCESS(status)) {
        goto err0;
    }

    /* Start filtering I/O. */
    status = FltStartFiltering(ScannerData.Filter);
    if (!NT_SUCCESS(status)) {
        goto err1;
    }

    return status;

err1: FltUnregisterFilter(ScannerData.Filter);
err0: return status;
}

/*++
    This is the unload routine for the Filter driver.  This unregisters the
    Filter with the filter manager and frees any allocated global data
    structures.

Return Value:
    Returns the final status of the deallocation routines.

--*/
NTSTATUS UnregisterFilesystemFilter (__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNICODE_STRING win32DeviceName;
    UNREFERENCED_PARAMETER(Flags);

    if (ScannerData.Filter) {
        /* Unregister the filter */
        FltUnregisterFilter(ScannerData.Filter);
    }

    return STATUS_SUCCESS;
}

/*++
Routine Description:

    This routine is called by the filter manager when a new instance is created.
    We specified in the registry that we only want for manual attachments,
    so that is all we should receive here.

Arguments:

    FltObjects - Describes the instance and volume which we are being asked to
        setup.

    Flags - Flags describing the type of attachment this is.

    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
        will attach.

    VolumeFileSystemType - The file system formatted on this volume.

Return Value:

  FLT_NOTIFY_STATUS_ATTACH              - we wish to attach to the volume
  FLT_NOTIFY_STATUS_DO_NOT_ATTACH       - no, thank you

--*/
NTSTATUS ScannerInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    ASSERT(FltObjects->Filter == ScannerData.Filter);

    /* Don't attach to network volumes. */
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/*++
    This is the instance detach routine for the filter. This
    routine is called by filter manager when a user initiates a manual instance
    detach. This is a 'query' routine: if the filter does not want to support
    manual detach, it can return a failure status

Arguments:

    FltObjects - Describes the instance and volume for which we are receiving
        this query teardown request.

    Flags - Unused

Return Value:

    STATUS_SUCCESS - we allow instance detach to happen

--*/
NTSTATUS ScannerQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PFLT_FILE_NAME_INFORMATION OpenFileName = NULL, NormalizedFileName = NULL;
    NTSTATUS Status;
    BOOLEAN HasTilda = FALSE;
    unsigned i;
    
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED, &OpenFileName);
    if (Status != STATUS_SUCCESS) {
        goto end;
    }

    for (i = 0; i < OpenFileName->Name.Length / sizeof(WCHAR); ++i) {
        if (OpenFileName->Name.Buffer[i] == '~') {
            HasTilda = TRUE;
            break;
        }
    }

    if (!HasTilda) {
        goto end;
    }
    
    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &NormalizedFileName);
    if (Status == STATUS_SUCCESS) {
        /* Some long names may have tildas as well */
        if (!RtlEqualUnicodeString(&OpenFileName->Name, &NormalizedFileName->Name, FALSE)) {
            WinMon2SendNormalizedName(&OpenFileName->Name, &NormalizedFileName->Name);
        }
        //S2EMessageFmt("lfidriver: %s Original:   %S", __FUNCTION__, OpenFileName->Name.Buffer);        
        //S2EMessageFmt("lfidriver: %s Normalized: %S", __FUNCTION__, NormalizedFileName->Name.Buffer);        
    }
    
    end:

    if (OpenFileName) {
        FltReleaseFileNameInformation(OpenFileName);
    }

    if (NormalizedFileName) {
        FltReleaseFileNameInformation(NormalizedFileName);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS MyRtlDuplicateUnicodeString(PUNICODE_STRING Dest, PUNICODE_STRING Source)
{
    *Dest = *Source;
    Dest->Buffer = (PWCH) ExAllocatePoolWithTag(NonPagedPool, Source->MaximumLength, 0xdead);
    if (!Dest->Buffer) {
        return STATUS_NO_MEMORY;
    }

    memcpy(Dest->Buffer, Source->Buffer, Source->MaximumLength);

    return STATUS_SUCCESS;
}

VOID MyRtlFreeUnicodeString(PUNICODE_STRING Str)
{
    ExFreePoolWithTag(Str->Buffer, 0xdead);
}
 