#define RUN_WPP

#include <Ntifs.h>
#include <wdm.h>
#include "s2e.h"
#include "symbhw.h"
#include "hook.h"
#include <ResourceTracker.h>

//ZwOpenKey
NTSTATUS
S2EHook_ZwOpenKey(
    /* OUT */ PHANDLE    KeyHandle,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_ATTRIBUTES    ObjectAttributes
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwOpenKey, "ZwOpenKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwOpenKey(    KeyHandle,    DesiredAccess,    ObjectAttributes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwOpenKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwOpenKey(    KeyHandle,    DesiredAccess,    ObjectAttributes);
        S2EMessageFmt("%s returned %#x\n", "ZwOpenKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwOpenKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmAllocatePagesForMdl
PMDL
S2EHook_MmAllocatePagesForMdl(
    /* IN */ PHYSICAL_ADDRESS    LowAddress,
    /* IN */ PHYSICAL_ADDRESS    HighAddress,
    /* IN */ PHYSICAL_ADDRESS    SkipBytes,
    /* IN */ SIZE_T    TotalBytes
)
{

    /* Variable declarations */PMDL RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmAllocatePagesForMdl, "MmAllocatePagesForMdl", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmAllocatePagesForMdl(    LowAddress,    HighAddress,    SkipBytes,    TotalBytes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmAllocatePagesForMdl", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmAllocatePagesForMdl(    LowAddress,    HighAddress,    SkipBytes,    TotalBytes);
        S2EMessageFmt("%s returned %#x\n", "MmAllocatePagesForMdl", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//MmAllocateContiguousMemorySpecifyCache
PVOID
S2EHook_MmAllocateContiguousMemorySpecifyCache(
    /* IN */ SIZE_T    NumberOfBytes,
    /* IN */ PHYSICAL_ADDRESS    LowestAcceptableAddress,
    /* IN */ PHYSICAL_ADDRESS    HighestAcceptableAddress,
    /* IN */ PHYSICAL_ADDRESS    BoundaryAddressMultiple,
    /* IN */ MEMORY_CACHING_TYPE    CacheType
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmAllocateContiguousMemorySpecifyCache, "MmAllocateContiguousMemorySpecifyCache", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmAllocateContiguousMemorySpecifyCache(    NumberOfBytes,    LowestAcceptableAddress,    HighestAcceptableAddress,    BoundaryAddressMultiple,    CacheType);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmAllocateContiguousMemorySpecifyCache", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmAllocateContiguousMemorySpecifyCache(    NumberOfBytes,    LowestAcceptableAddress,    HighestAcceptableAddress,    BoundaryAddressMultiple,    CacheType);
        S2EMessageFmt("%s returned %#x\n", "MmAllocateContiguousMemorySpecifyCache", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//IoGetDeviceObjectPointer
NTSTATUS
S2EHook_IoGetDeviceObjectPointer(
    /* IN */ PUNICODE_STRING    ObjectName,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* OUT */ PFILE_OBJECT*    FileObject,
    /* OUT */ PDEVICE_OBJECT*    DeviceObject
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoGetDeviceObjectPointer, "IoGetDeviceObjectPointer", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoGetDeviceObjectPointer(    ObjectName,    DesiredAccess,    FileObject,    DeviceObject);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoGetDeviceObjectPointer", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoGetDeviceObjectPointer(    ObjectName,    DesiredAccess,    FileObject,    DeviceObject);
        S2EMessageFmt("%s returned %#x\n", "IoGetDeviceObjectPointer", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoGetDeviceObjectPointer", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 5,    STATUS_INVALID_PARAMETER,    STATUS_INSUFFICIENT_RESOURCES,    STATUS_PRIVILEGE_NOT_HELD,    STATUS_OBJECT_TYPE_MISMATCH,    STATUS_OBJECT_NAME_INVALID);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmProtectMdlSystemAddress
NTSTATUS
S2EHook_MmProtectMdlSystemAddress(
    /* IN */ PMDL    MemoryDescriptorList,
    /* IN */ ULONG    NewProtect
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmProtectMdlSystemAddress, "MmProtectMdlSystemAddress", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmProtectMdlSystemAddress(    MemoryDescriptorList,    NewProtect);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmProtectMdlSystemAddress", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmProtectMdlSystemAddress(    MemoryDescriptorList,    NewProtect);
        S2EMessageFmt("%s returned %#x\n", "MmProtectMdlSystemAddress", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PAGE_PROTECTION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_MmProtectMdlSystemAddress", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_PAGE_PROTECTION,    STATUS_NOT_MAPPED_VIEW);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIQuerySingleInstance
NTSTATUS
S2EHook_IoWMIQuerySingleInstance(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ PUNICODE_STRING    InstanceName,
    /* IN */ ULONG*    InOutBufferSize,
    /* OUT */ PVOID    OutBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIQuerySingleInstance, "IoWMIQuerySingleInstance", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIQuerySingleInstance(    DataBlockObject,    InstanceName,    InOutBufferSize,    OutBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIQuerySingleInstance", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIQuerySingleInstance(    DataBlockObject,    InstanceName,    InOutBufferSize,    OutBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMIQuerySingleInstance", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_INSTANCE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIQuerySingleInstance", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_WMI_INSTANCE_NOT_FOUND,    STATUS_WMI_GUID_NOT_FOUND,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExAllocatePoolWithQuota
PVOID
S2EHook_ExAllocatePoolWithQuota(
    /* IN */ POOL_TYPE    PoolType,
    /* IN */ SIZE_T    NumberOfBytes
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExAllocatePoolWithQuota, "ExAllocatePoolWithQuota", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExAllocatePoolWithQuota(    PoolType,    NumberOfBytes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExAllocatePoolWithQuota", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExAllocatePoolWithQuota(    PoolType,    NumberOfBytes);
        S2EMessageFmt("%s returned %#x\n", "ExAllocatePoolWithQuota", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();

        if (PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE) {
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }
        return NULL;

    }
}

//ObReferenceObjectByPointer
NTSTATUS
S2EHook_ObReferenceObjectByPointer(
    /* IN */ PVOID    Object,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_TYPE    ObjectType,
    /* IN */ KPROCESSOR_MODE    AccessMode
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ObReferenceObjectByPointer, "ObReferenceObjectByPointer", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ObReferenceObjectByPointer(    Object,    DesiredAccess,    ObjectType,    AccessMode);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ObReferenceObjectByPointer", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ObReferenceObjectByPointer(    Object,    DesiredAccess,    ObjectType,    AccessMode);
        S2EMessageFmt("%s returned %#x\n", "ObReferenceObjectByPointer", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_TYPE_MISMATCH, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ObReferenceObjectByPointer", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_OBJECT_TYPE_MISMATCH);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//PsSetCreateThreadNotifyRoutine
NTSTATUS
S2EHook_PsSetCreateThreadNotifyRoutine(
    /* IN */ PCREATE_THREAD_NOTIFY_ROUTINE    NotifyRoutine
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PsSetCreateThreadNotifyRoutine, "PsSetCreateThreadNotifyRoutine", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PsSetCreateThreadNotifyRoutine(    NotifyRoutine);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PsSetCreateThreadNotifyRoutine", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PsSetCreateThreadNotifyRoutine(    NotifyRoutine);
        S2EMessageFmt("%s returned %#x\n", "PsSetCreateThreadNotifyRoutine", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INSUFFICIENT_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_PsSetCreateThreadNotifyRoutine", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoGetBootDiskInformation
NTSTATUS
S2EHook_IoGetBootDiskInformation(
    /* IN */ PBOOTDISK_INFORMATION    BootDiskInformation,
    /* IN */ ULONG    Size
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoGetBootDiskInformation, "IoGetBootDiskInformation", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoGetBootDiskInformation(    BootDiskInformation,    Size);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoGetBootDiskInformation", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoGetBootDiskInformation(    BootDiskInformation,    Size);
        S2EMessageFmt("%s returned %#x\n", "IoGetBootDiskInformation", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_TOO_LATE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoGetBootDiskInformation", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_TOO_LATE,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlInt64ToUnicodeString
NTSTATUS
S2EHook_RtlInt64ToUnicodeString(
    /* IN */ ULONGLONG    Value,
    /* IN */ ULONG    Base,
    /* IN */ PUNICODE_STRING    String
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlInt64ToUnicodeString, "RtlInt64ToUnicodeString", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlInt64ToUnicodeString(    Value,    Base,    String);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlInt64ToUnicodeString", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlInt64ToUnicodeString(    Value,    Base,    String);
        S2EMessageFmt("%s returned %#x\n", "RtlInt64ToUnicodeString", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlInt64ToUnicodeString", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_BUFFER_OVERFLOW,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//SeAssignSecurityEx
NTSTATUS
S2EHook_SeAssignSecurityEx(
    /* IN */ PSECURITY_DESCRIPTOR    ParentDescriptor,
    /* IN */ PSECURITY_DESCRIPTOR    ExplicitDescriptor,
    /* OUT */ PSECURITY_DESCRIPTOR*    NewDescriptor,
    /* IN */ GUID*    ObjectType,
    /* IN */ BOOLEAN    IsDirectoryObject,
    /* IN */ ULONG    AutoInheritFlags,
    /* IN */ PSECURITY_SUBJECT_CONTEXT    SubjectContext,
    /* IN */ PGENERIC_MAPPING    GenericMapping,
    /* IN */ POOL_TYPE    PoolType
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&SeAssignSecurityEx, "SeAssignSecurityEx", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = SeAssignSecurityEx(    ParentDescriptor,    ExplicitDescriptor,    NewDescriptor,    ObjectType,    IsDirectoryObject,    AutoInheritFlags,    SubjectContext,    GenericMapping,    PoolType);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_SeAssignSecurityEx", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = SeAssignSecurityEx(    ParentDescriptor,    ExplicitDescriptor,    NewDescriptor,    ObjectType,    IsDirectoryObject,    AutoInheritFlags,    SubjectContext,    GenericMapping,    PoolType);
        S2EMessageFmt("%s returned %#x\n", "SeAssignSecurityEx", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_OWNER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_SeAssignSecurityEx", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_OWNER,    STATUS_PRIVILEGE_NOT_HELD);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//PsRemoveCreateThreadNotifyRoutine
NTSTATUS
S2EHook_PsRemoveCreateThreadNotifyRoutine(
    /* IN */ PCREATE_THREAD_NOTIFY_ROUTINE    NotifyRoutine
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PsRemoveCreateThreadNotifyRoutine, "PsRemoveCreateThreadNotifyRoutine", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PsRemoveCreateThreadNotifyRoutine(    NotifyRoutine);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PsRemoveCreateThreadNotifyRoutine", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PsRemoveCreateThreadNotifyRoutine(    NotifyRoutine);
        S2EMessageFmt("%s returned %#x\n", "PsRemoveCreateThreadNotifyRoutine", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_PROCEDURE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_PsRemoveCreateThreadNotifyRoutine", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_PROCEDURE_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoGetDeviceProperty
NTSTATUS
S2EHook_IoGetDeviceProperty(
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* IN */ DEVICE_REGISTRY_PROPERTY    DeviceProperty,
    /* IN */ ULONG    BufferLength,
    /* OUT */ PVOID    PropertyBuffer,
    /* OUT */ PULONG    ResultLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoGetDeviceProperty, "IoGetDeviceProperty", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoGetDeviceProperty(    DeviceObject,    DeviceProperty,    BufferLength,    PropertyBuffer,    ResultLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoGetDeviceProperty", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoGetDeviceProperty(    DeviceObject,    DeviceProperty,    BufferLength,    PropertyBuffer,    ResultLength);
        S2EMessageFmt("%s returned %#x\n", "IoGetDeviceProperty", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_DEVICE_REQUEST, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoGetDeviceProperty", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_INVALID_DEVICE_REQUEST,    STATUS_INVALID_PARAMETER_2,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwDeleteValueKey
NTSTATUS
S2EHook_ZwDeleteValueKey(
    /* IN */ HANDLE    KeyHandle,
    /* IN */ PUNICODE_STRING    ValueName
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwDeleteValueKey, "ZwDeleteValueKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwDeleteValueKey(    KeyHandle,    ValueName);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwDeleteValueKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwDeleteValueKey(    KeyHandle,    ValueName);
        S2EMessageFmt("%s returned %#x\n", "ZwDeleteValueKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwDeleteValueKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    STATUS_OBJECT_NAME_NOT_FOUND,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIQueryAllDataMultiple
NTSTATUS
S2EHook_IoWMIQueryAllDataMultiple(
    /* IN */ PVOID*    DataBlockObjectList,
    /* IN */ ULONG    ObjectCount,
    /* IN */ ULONG*    InOutBufferSize,
    /* OUT */ PVOID    OutBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIQueryAllDataMultiple, "IoWMIQueryAllDataMultiple", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIQueryAllDataMultiple(    DataBlockObjectList,    ObjectCount,    InOutBufferSize,    OutBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIQueryAllDataMultiple", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIQueryAllDataMultiple(    DataBlockObjectList,    ObjectCount,    InOutBufferSize,    OutBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMIQueryAllDataMultiple", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_TOO_SMALL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIQueryAllDataMultiple", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExRegisterCallback
PVOID
S2EHook_ExRegisterCallback(
    /* IN */ PCALLBACK_OBJECT    CallbackObject,
    /* IN */ PCALLBACK_FUNCTION    CallbackFunction,
    /* IN */ PVOID    CallbackContext
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExRegisterCallback, "ExRegisterCallback", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExRegisterCallback(    CallbackObject,    CallbackFunction,    CallbackContext);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExRegisterCallback", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExRegisterCallback(    CallbackObject,    CallbackFunction,    CallbackContext);
        S2EMessageFmt("%s returned %#x\n", "ExRegisterCallback", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//ZwQueryValueKey
NTSTATUS
S2EHook_ZwQueryValueKey(
    /* IN */ HANDLE    KeyHandle,
    /* IN */ PUNICODE_STRING    ValueName,
    /* IN */ KEY_VALUE_INFORMATION_CLASS    KeyValueInformationClass,
    /* OUT */ PVOID    KeyValueInformation,
    /* IN */ ULONG    Length,
    /* OUT */ PULONG    ResultLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwQueryValueKey, "ZwQueryValueKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwQueryValueKey(    KeyHandle,    ValueName,    KeyValueInformationClass,    KeyValueInformation,    Length,    ResultLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwQueryValueKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwQueryValueKey(    KeyHandle,    ValueName,    KeyValueInformationClass,    KeyValueInformation,    Length,    ResultLength);
        S2EMessageFmt("%s returned %#x\n", "ZwQueryValueKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwQueryValueKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_BUFFER_OVERFLOW,    STATUS_INVALID_PARAMETER,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIExecuteMethod
NTSTATUS
S2EHook_IoWMIExecuteMethod(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ PUNICODE_STRING    InstanceName,
    /* IN */ ULONG    MethodId,
    /* IN */ ULONG    InBufferSize,
    /* IN */ PULONG    OutBufferSize,
    /* IN */ PUCHAR    InOutBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIExecuteMethod, "IoWMIExecuteMethod", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIExecuteMethod(    DataBlockObject,    InstanceName,    MethodId,    InBufferSize,    OutBufferSize,    InOutBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIExecuteMethod", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIExecuteMethod(    DataBlockObject,    InstanceName,    MethodId,    InBufferSize,    OutBufferSize,    InOutBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMIExecuteMethod", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_INSTANCE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIExecuteMethod", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    STATUS_WMI_INSTANCE_NOT_FOUND,    STATUS_WMI_ITEMID_NOT_FOUND,    STATUS_WMI_GUID_NOT_FOUND,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlUnicodeStringToInteger
NTSTATUS
S2EHook_RtlUnicodeStringToInteger(
    /* IN */ PUNICODE_STRING    String,
    /* IN */ ULONG    Base,
    /* OUT */ PULONG    Value
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlUnicodeStringToInteger, "RtlUnicodeStringToInteger", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlUnicodeStringToInteger(    String,    Base,    Value);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlUnicodeStringToInteger", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlUnicodeStringToInteger(    String,    Base,    Value);
        S2EMessageFmt("%s returned %#x\n", "RtlUnicodeStringToInteger", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlUnicodeStringToInteger", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMISuggestInstanceName
NTSTATUS
S2EHook_IoWMISuggestInstanceName(
    /* IN */ PDEVICE_OBJECT    PhysicalDeviceObject,
    /* IN */ PUNICODE_STRING    SymbolicLinkName,
    /* IN */ BOOLEAN    CombineNames,
    /* OUT */ PUNICODE_STRING    SuggestedInstanceName
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMISuggestInstanceName, "IoWMISuggestInstanceName", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMISuggestInstanceName(    PhysicalDeviceObject,    SymbolicLinkName,    CombineNames,    SuggestedInstanceName);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMISuggestInstanceName", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMISuggestInstanceName(    PhysicalDeviceObject,    SymbolicLinkName,    CombineNames,    SuggestedInstanceName);
        S2EMessageFmt("%s returned %#x\n", "IoWMISuggestInstanceName", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_UNSUCCESSFUL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMISuggestInstanceName", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_UNSUCCESSFUL,    STATUS_NO_MEMORY,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoSetDeviceInterfaceState
NTSTATUS
S2EHook_IoSetDeviceInterfaceState(
    /* IN */ PUNICODE_STRING    SymbolicLinkName,
    /* IN */ BOOLEAN    Enable
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoSetDeviceInterfaceState, "IoSetDeviceInterfaceState", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoSetDeviceInterfaceState(    SymbolicLinkName,    Enable);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoSetDeviceInterfaceState", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoSetDeviceInterfaceState(    SymbolicLinkName,    Enable);
        S2EMessageFmt("%s returned %#x\n", "IoSetDeviceInterfaceState", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoSetDeviceInterfaceState", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_OBJECT_NAME_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlCharToInteger
NTSTATUS
S2EHook_RtlCharToInteger(
    /* IN */ PCSZ    String,
    /* IN */ ULONG    Base,
    /* IN */ PULONG    Value
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlCharToInteger, "RtlCharToInteger", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlCharToInteger(    String,    Base,    Value);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlCharToInteger", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlCharToInteger(    String,    Base,    Value);
        S2EMessageFmt("%s returned %#x\n", "RtlCharToInteger", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlCharToInteger", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ObReferenceObjectByHandle
NTSTATUS
S2EHook_ObReferenceObjectByHandle(
    /* IN */ HANDLE    Handle,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_TYPE    ObjectType,
    /* IN */ KPROCESSOR_MODE    AccessMode,
    /* OUT */ PVOID*    Object,
    /* OUT */ POBJECT_HANDLE_INFORMATION    HandleInformation
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ObReferenceObjectByHandle, "ObReferenceObjectByHandle", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ObReferenceObjectByHandle(    Handle,    DesiredAccess,    ObjectType,    AccessMode,    Object,    HandleInformation);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ObReferenceObjectByHandle", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ObReferenceObjectByHandle(    Handle,    DesiredAccess,    ObjectType,    AccessMode,    Object,    HandleInformation);
        S2EMessageFmt("%s returned %#x\n", "ObReferenceObjectByHandle", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_TYPE_MISMATCH, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ObReferenceObjectByHandle", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_OBJECT_TYPE_MISMATCH,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();
        *Object = NULL;

        return ConcolicStatus;
    }
}

//ExAllocatePoolWithQuotaTag
PVOID
S2EHook_ExAllocatePoolWithQuotaTag(
    /* IN */ POOL_TYPE    PoolType,
    /* IN */ SIZE_T    NumberOfBytes,
    /* IN */ ULONG    Tag
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExAllocatePoolWithQuotaTag, "ExAllocatePoolWithQuotaTag", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExAllocatePoolWithQuotaTag(    PoolType,    NumberOfBytes,    Tag);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExAllocatePoolWithQuotaTag", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExAllocatePoolWithQuotaTag(    PoolType,    NumberOfBytes,    Tag);
        S2EMessageFmt("%s returned %#x\n", "ExAllocatePoolWithQuotaTag", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();

        if (PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE) {
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }
        return NULL;

    }
}

//RtlAppendUnicodeToString
NTSTATUS
S2EHook_RtlAppendUnicodeToString(
    /* IN */ PUNICODE_STRING    Destination,
    /* IN */ PCWSTR    Source
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlAppendUnicodeToString, "RtlAppendUnicodeToString", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlAppendUnicodeToString(    Destination,    Source);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlAppendUnicodeToString", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlAppendUnicodeToString(    Destination,    Source);
        S2EMessageFmt("%s returned %#x\n", "RtlAppendUnicodeToString", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_TOO_SMALL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlAppendUnicodeToString", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoReportTargetDeviceChangeAsynchronous
NTSTATUS
S2EHook_IoReportTargetDeviceChangeAsynchronous(
    /* IN */ PDEVICE_OBJECT    PhysicalDeviceObject,
    /* IN */ PVOID    NotificationStructure,
    /* IN */ PDEVICE_CHANGE_COMPLETE_CALLBACK    Callback,
    /* IN */ PVOID    Context
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoReportTargetDeviceChangeAsynchronous, "IoReportTargetDeviceChangeAsynchronous", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoReportTargetDeviceChangeAsynchronous(    PhysicalDeviceObject,    NotificationStructure,    Callback,    Context);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoReportTargetDeviceChangeAsynchronous", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoReportTargetDeviceChangeAsynchronous(    PhysicalDeviceObject,    NotificationStructure,    Callback,    Context);
        S2EMessageFmt("%s returned %#x\n", "IoReportTargetDeviceChangeAsynchronous", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_DEVICE_REQUEST, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoReportTargetDeviceChangeAsynchronous", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_DEVICE_REQUEST);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoAllocateIrp
PIRP
S2EHook_IoAllocateIrp(
    /* IN */ CCHAR    StackSize,
    /* IN */ BOOLEAN    ChargeQuota
)
{

    /* Variable declarations */PIRP RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoAllocateIrp, "IoAllocateIrp", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoAllocateIrp(    StackSize,    ChargeQuota);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoAllocateIrp", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoAllocateIrp(    StackSize,    ChargeQuota);
        S2EMessageFmt("%s returned %#x\n", "IoAllocateIrp", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//PsSetCreateProcessNotifyRoutine
NTSTATUS
S2EHook_PsSetCreateProcessNotifyRoutine(
    /* IN */ PCREATE_PROCESS_NOTIFY_ROUTINE    NotifyRoutine,
    /* IN */ BOOLEAN    Remove
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PsSetCreateProcessNotifyRoutine, "PsSetCreateProcessNotifyRoutine", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PsSetCreateProcessNotifyRoutine(    NotifyRoutine,    Remove);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PsSetCreateProcessNotifyRoutine", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PsSetCreateProcessNotifyRoutine(    NotifyRoutine,    Remove);
        S2EMessageFmt("%s returned %#x\n", "PsSetCreateProcessNotifyRoutine", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_PsSetCreateProcessNotifyRoutine", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmMapIoSpace
PVOID
S2EHook_MmMapIoSpace(
    /* IN */ PHYSICAL_ADDRESS    PhysicalAddress,
    /* IN */ ULONG    NumberOfBytes,
    /* IN */ MEMORY_CACHING_TYPE    CacheEnable
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmMapIoSpace, "MmMapIoSpace", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmMapIoSpace(    PhysicalAddress,    NumberOfBytes,    CacheEnable);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmMapIoSpace", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmMapIoSpace(    PhysicalAddress,    NumberOfBytes,    CacheEnable);
        S2EMessageFmt("%s returned %#x\n", "MmMapIoSpace", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//ZwDeviceIoControlFile
NTSTATUS
S2EHook_ZwDeviceIoControlFile(
    /* IN */ HANDLE    DeviceHandle,
    /* IN */ HANDLE    Event,
    /* IN */ PIO_APC_ROUTINE    UserApcRoutine,
    /* IN */ PVOID    UserApcContext,
    /* OUT */ PIO_STATUS_BLOCK    IoStatusBlock,
    /* IN */ ULONG    IoControlCode,
    /* IN */ PVOID    InputBuffer,
    /* IN */ ULONG    InputBufferSize,
    /* OUT */ PVOID    OutputBuffer,
    /* IN */ ULONG    OutputBufferSize
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwDeviceIoControlFile, "ZwDeviceIoControlFile", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwDeviceIoControlFile(    DeviceHandle,    Event,    UserApcRoutine,    UserApcContext,    IoStatusBlock,    IoControlCode,    InputBuffer,    InputBufferSize,    OutputBuffer,    OutputBufferSize);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwDeviceIoControlFile", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwDeviceIoControlFile(    DeviceHandle,    Event,    UserApcRoutine,    UserApcContext,    IoStatusBlock,    IoControlCode,    InputBuffer,    InputBufferSize,    OutputBuffer,    OutputBufferSize);
        S2EMessageFmt("%s returned %#x\n", "ZwDeviceIoControlFile", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwDeviceIoControlFile", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 5,    STATUS_INVALID_PARAMETER,    STATUS_INSUFFICIENT_RESOURCES,    STATUS_OBJECT_TYPE_MISMATCH,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoOpenDeviceInterfaceRegistryKey
NTSTATUS
S2EHook_IoOpenDeviceInterfaceRegistryKey(
    /* IN */ PUNICODE_STRING    SymbolicLinkName,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* OUT */ PHANDLE    DeviceInterfaceKey
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoOpenDeviceInterfaceRegistryKey, "IoOpenDeviceInterfaceRegistryKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoOpenDeviceInterfaceRegistryKey(    SymbolicLinkName,    DesiredAccess,    DeviceInterfaceKey);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoOpenDeviceInterfaceRegistryKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoOpenDeviceInterfaceRegistryKey(    SymbolicLinkName,    DesiredAccess,    DeviceInterfaceKey);
        S2EMessageFmt("%s returned %#x\n", "IoOpenDeviceInterfaceRegistryKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoOpenDeviceInterfaceRegistryKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_OBJECT_NAME_NOT_FOUND,    STATUS_INVALID_PARAMETER,    STATUS_OBJECT_PATH_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//PoRequestPowerIrp
NTSTATUS
S2EHook_PoRequestPowerIrp(
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* IN */ UCHAR    MinorFunction,
    /* IN */ POWER_STATE    PowerState,
    /* IN */ PREQUEST_POWER_COMPLETE    CompletionFunction,
    /* IN */ PVOID    Context,
    /* OUT */ PIRP*    Irp
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PoRequestPowerIrp, "PoRequestPowerIrp", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PoRequestPowerIrp(    DeviceObject,    MinorFunction,    PowerState,    CompletionFunction,    Context,    Irp);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PoRequestPowerIrp", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PoRequestPowerIrp(    DeviceObject,    MinorFunction,    PowerState,    CompletionFunction,    Context,    Irp);
        S2EMessageFmt("%s returned %#x\n", "PoRequestPowerIrp", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER_2, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_PoRequestPowerIrp", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_PARAMETER_2,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoAllocateMdl
PMDL
S2EHook_IoAllocateMdl(
    /* IN */ PVOID    VirtualAddress,
    /* IN */ ULONG    Length,
    /* IN */ BOOLEAN    SecondaryBuffer,
    /* IN */ BOOLEAN    ChargeQuota,
    /* IN */ PIRP    Irp
)
{

    /* Variable declarations */PMDL RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoAllocateMdl, "IoAllocateMdl", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoAllocateMdl(    VirtualAddress,    Length,    SecondaryBuffer,    ChargeQuota,    Irp);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoAllocateMdl", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoAllocateMdl(    VirtualAddress,    Length,    SecondaryBuffer,    ChargeQuota,    Irp);
        S2EMessageFmt("%s returned %#x\n", "IoAllocateMdl", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//RtlSetDaclSecurityDescriptor
NTSTATUS
S2EHook_RtlSetDaclSecurityDescriptor(
    /* IN */ PSECURITY_DESCRIPTOR    SecurityDescriptor,
    /* IN */ BOOLEAN    DaclPresent,
    /* IN */ PACL    Dacl,
    /* IN */ BOOLEAN    DaclDefaulted
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlSetDaclSecurityDescriptor, "RtlSetDaclSecurityDescriptor", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlSetDaclSecurityDescriptor(    SecurityDescriptor,    DaclPresent,    Dacl,    DaclDefaulted);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlSetDaclSecurityDescriptor", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlSetDaclSecurityDescriptor(    SecurityDescriptor,    DaclPresent,    Dacl,    DaclDefaulted);
        S2EMessageFmt("%s returned %#x\n", "RtlSetDaclSecurityDescriptor", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_UNKNOWN_REVISION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlSetDaclSecurityDescriptor", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_UNKNOWN_REVISION,    STATUS_INVALID_SECURITY_DESCR);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwSetValueKey
NTSTATUS
S2EHook_ZwSetValueKey(
    /* IN */ HANDLE    KeyHandle,
    /* IN */ PUNICODE_STRING    ValueName,
    /* IN */ ULONG    TitleIndex,
    /* IN */ ULONG    Type,
    /* IN */ PVOID    Data,
    /* IN */ ULONG    DataSize
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwSetValueKey, "ZwSetValueKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwSetValueKey(    KeyHandle,    ValueName,    TitleIndex,    Type,    Data,    DataSize);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwSetValueKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwSetValueKey(    KeyHandle,    ValueName,    TitleIndex,    Type,    Data,    DataSize);
        S2EMessageFmt("%s returned %#x\n", "ZwSetValueKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwSetValueKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//CmUnRegisterCallback
NTSTATUS
S2EHook_CmUnRegisterCallback(
    /* IN */ LARGE_INTEGER    Cookie
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&CmUnRegisterCallback, "CmUnRegisterCallback", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = CmUnRegisterCallback(    Cookie);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_CmUnRegisterCallback", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = CmUnRegisterCallback(    Cookie);
        S2EMessageFmt("%s returned %#x\n", "CmUnRegisterCallback", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_CmUnRegisterCallback", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwEnumerateValueKey
NTSTATUS
S2EHook_ZwEnumerateValueKey(
    /* IN */ HANDLE    KeyHandle,
    /* IN */ ULONG    Index,
    /* IN */ KEY_VALUE_INFORMATION_CLASS    KeyValueInformationClass,
    /* OUT */ PVOID    KeyValueInformation,
    /* IN */ ULONG    Length,
    /* OUT */ PULONG    ResultLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwEnumerateValueKey, "ZwEnumerateValueKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwEnumerateValueKey(    KeyHandle,    Index,    KeyValueInformationClass,    KeyValueInformation,    Length,    ResultLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwEnumerateValueKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwEnumerateValueKey(    KeyHandle,    Index,    KeyValueInformationClass,    KeyValueInformation,    Length,    ResultLength);
        S2EMessageFmt("%s returned %#x\n", "ZwEnumerateValueKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwEnumerateValueKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    STATUS_BUFFER_OVERFLOW,    STATUS_NO_MORE_ENTRIES,    STATUS_INVALID_PARAMETER,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwWaitForSingleObject
NTSTATUS
S2EHook_ZwWaitForSingleObject(
    /* IN */ HANDLE    Object,
    /* IN */ BOOLEAN    Alertable,
    /* IN */ PLARGE_INTEGER    Time
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwWaitForSingleObject, "ZwWaitForSingleObject", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwWaitForSingleObject(    Object,    Alertable,    Time);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwWaitForSingleObject", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwWaitForSingleObject(    Object,    Alertable,    Time);
        S2EMessageFmt("%s returned %#x\n", "ZwWaitForSingleObject", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwWaitForSingleObject", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwCreateEvent
NTSTATUS
S2EHook_ZwCreateEvent(
    /* OUT */ PHANDLE    EventHandle,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_ATTRIBUTES    ObjectAttributes,
    /* IN */ BOOLEAN    ManualReset,
    /* IN */ BOOLEAN    InitialState
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwCreateEvent, "ZwCreateEvent", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwCreateEvent(    EventHandle,    DesiredAccess,    ObjectAttributes,    ManualReset,    InitialState);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwCreateEvent", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwCreateEvent(    EventHandle,    DesiredAccess,    ObjectAttributes,    ManualReset,    InitialState);
        S2EMessageFmt("%s returned %#x\n", "ZwCreateEvent", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER_4, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwCreateEvent", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 6,    STATUS_INVALID_PARAMETER_4,    STATUS_INVALID_PARAMETER,    STATUS_INSUFFICIENT_RESOURCES,    STATUS_PRIVILEGE_NOT_HELD,    STATUS_OBJECT_PATH_SYNTAX_BAD,    STATUS_OBJECT_NAME_INVALID);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlVerifyVersionInfo
NTSTATUS
S2EHook_RtlVerifyVersionInfo(
    /* IN */ PRTL_OSVERSIONINFOEXW    VersionInfo,
    /* IN */ ULONG    TypeMask,
    /* IN */ ULONGLONG    ConditionMask
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlVerifyVersionInfo, "RtlVerifyVersionInfo", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlVerifyVersionInfo(    VersionInfo,    TypeMask,    ConditionMask);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlVerifyVersionInfo", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlVerifyVersionInfo(    VersionInfo,    TypeMask,    ConditionMask);
        S2EMessageFmt("%s returned %#x\n", "RtlVerifyVersionInfo", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_REVISION_MISMATCH, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlVerifyVersionInfo", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_REVISION_MISMATCH,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoAllocateDriverObjectExtension
NTSTATUS
S2EHook_IoAllocateDriverObjectExtension(
    /* IN */ PDRIVER_OBJECT    DriverObject,
    /* IN */ PVOID    ClientIdentificationAddress,
    /* IN */ ULONG    DriverObjectExtensionSize,
    /* OUT */ PVOID*    DriverObjectExtension
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoAllocateDriverObjectExtension, "IoAllocateDriverObjectExtension", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoAllocateDriverObjectExtension(    DriverObject,    ClientIdentificationAddress,    DriverObjectExtensionSize,    DriverObjectExtension);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoAllocateDriverObjectExtension", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoAllocateDriverObjectExtension(    DriverObject,    ClientIdentificationAddress,    DriverObjectExtensionSize,    DriverObjectExtension);
        S2EMessageFmt("%s returned %#x\n", "IoAllocateDriverObjectExtension", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_COLLISION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoAllocateDriverObjectExtension", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_OBJECT_NAME_COLLISION,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwCreateFile
NTSTATUS
S2EHook_ZwCreateFile(
    /* OUT */ PHANDLE    FileHandle,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_ATTRIBUTES    ObjectAttributes,
    /* OUT */ PIO_STATUS_BLOCK    IoStatusBlock,
    /* IN */ PLARGE_INTEGER    AllocationSize,
    /* IN */ ULONG    FileAttributes,
    /* IN */ ULONG    ShareAccess,
    /* IN */ ULONG    CreateDisposition,
    /* IN */ ULONG    CreateOptions,
    /* IN */ PVOID    EaBuffer,
    /* IN */ ULONG    EaLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwCreateFile, "ZwCreateFile", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwCreateFile(    FileHandle,    DesiredAccess,    ObjectAttributes,    IoStatusBlock,    AllocationSize,    FileAttributes,    ShareAccess,    CreateDisposition,    CreateOptions,    EaBuffer,    EaLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwCreateFile", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwCreateFile(    FileHandle,    DesiredAccess,    ObjectAttributes,    IoStatusBlock,    AllocationSize,    FileAttributes,    ShareAccess,    CreateDisposition,    CreateOptions,    EaBuffer,    EaLength);
        S2EMessageFmt("%s returned %#x\n", "ZwCreateFile", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_FILE_LOCK_CONFLICT, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwCreateFile", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_FILE_LOCK_CONFLICT);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//DbgPrint
ULONG
S2EHook_DbgPrint(
    /*  */ PCH    Format, ...
)
{



    S2EMessageFmt("DbgPrint %s\n", Format);

    return STATUS_SUCCESS;



}

//MmAllocateContiguousMemory
PVOID
S2EHook_MmAllocateContiguousMemory(
    /* IN */ ULONG    NumberOfBytes,
    /* IN */ PHYSICAL_ADDRESS    HighestAcceptableAddress
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmAllocateContiguousMemory, "MmAllocateContiguousMemory", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmAllocateContiguousMemory(    NumberOfBytes,    HighestAcceptableAddress);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmAllocateContiguousMemory", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmAllocateContiguousMemory(    NumberOfBytes,    HighestAcceptableAddress);
        S2EMessageFmt("%s returned %#x\n", "MmAllocateContiguousMemory", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//SeAssignSecurity
NTSTATUS
S2EHook_SeAssignSecurity(
    /* IN */ PSECURITY_DESCRIPTOR    ParentDescriptor,
    /* IN */ PSECURITY_DESCRIPTOR    ExplicitDescriptor,
    /* OUT */ PSECURITY_DESCRIPTOR*    NewDescriptor,
    /* IN */ BOOLEAN    IsDirectoryObject,
    /* IN */ PSECURITY_SUBJECT_CONTEXT    SubjectContext,
    /* IN */ PGENERIC_MAPPING    GenericMapping,
    /* IN */ POOL_TYPE    PoolType
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&SeAssignSecurity, "SeAssignSecurity", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = SeAssignSecurity(    ParentDescriptor,    ExplicitDescriptor,    NewDescriptor,    IsDirectoryObject,    SubjectContext,    GenericMapping,    PoolType);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_SeAssignSecurity", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = SeAssignSecurity(    ParentDescriptor,    ExplicitDescriptor,    NewDescriptor,    IsDirectoryObject,    SubjectContext,    GenericMapping,    PoolType);
        S2EMessageFmt("%s returned %#x\n", "SeAssignSecurity", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_OWNER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_SeAssignSecurity", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_OWNER,    STATUS_PRIVILEGE_NOT_HELD);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwOpenSection
NTSTATUS
S2EHook_ZwOpenSection(
    /* OUT */ PHANDLE    SectionHandle,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_ATTRIBUTES    ObjectAttributes
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwOpenSection, "ZwOpenSection", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwOpenSection(    SectionHandle,    DesiredAccess,    ObjectAttributes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwOpenSection", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwOpenSection(    SectionHandle,    DesiredAccess,    ObjectAttributes);
        S2EMessageFmt("%s returned %#x\n", "ZwOpenSection", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwOpenSection", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//PoRegisterSystemState
PVOID
S2EHook_PoRegisterSystemState(
    /* IN */ PVOID    StateHandle,
    /* IN */ EXECUTION_STATE    Flags
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PoRegisterSystemState, "PoRegisterSystemState", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PoRegisterSystemState(    StateHandle,    Flags);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PoRegisterSystemState", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PoRegisterSystemState(    StateHandle,    Flags);
        S2EMessageFmt("%s returned %#x\n", "PoRegisterSystemState", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//IoGetDeviceInterfaces
NTSTATUS
S2EHook_IoGetDeviceInterfaces(
    /* IN */ GUID*    InterfaceClassGuid,
    /* IN */ PDEVICE_OBJECT    PhysicalDeviceObject,
    /* IN */ ULONG    Flags,
    /* OUT */ PWSTR*    SymbolicLinkList
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoGetDeviceInterfaces, "IoGetDeviceInterfaces", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoGetDeviceInterfaces(    InterfaceClassGuid,    PhysicalDeviceObject,    Flags,    SymbolicLinkList);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoGetDeviceInterfaces", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoGetDeviceInterfaces(    InterfaceClassGuid,    PhysicalDeviceObject,    Flags,    SymbolicLinkList);
        S2EMessageFmt("%s returned %#x\n", "IoGetDeviceInterfaces", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_DEVICE_REQUEST, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoGetDeviceInterfaces", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_DEVICE_REQUEST);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwClose
NTSTATUS
S2EHook_ZwClose(
    /* IN */ HANDLE    Handle
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwClose, "ZwClose", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwClose(    Handle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwClose", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwClose(    Handle);
        S2EMessageFmt("%s returned %#x\n", "ZwClose", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_HANDLE_NOT_CLOSABLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwClose", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_HANDLE_NOT_CLOSABLE,    STATUS_INVALID_HANDLE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExAllocatePoolWithTagPriority
PVOID
S2EHook_ExAllocatePoolWithTagPriority(
    /* IN */ POOL_TYPE    PoolType,
    /* IN */ SIZE_T    NumberOfBytes,
    /* IN */ ULONG    Tag,
    /* IN */ EX_POOL_PRIORITY    Priority
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExAllocatePoolWithTagPriority, "ExAllocatePoolWithTagPriority", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExAllocatePoolWithTagPriority(    PoolType,    NumberOfBytes,    Tag,    Priority);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExAllocatePoolWithTagPriority", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExAllocatePoolWithTagPriority(    PoolType,    NumberOfBytes,    Tag,    Priority);
        S2EMessageFmt("%s returned %#x\n", "ExAllocatePoolWithTagPriority", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();

        if (PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE) {
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }
        return NULL;

    }
}

//KeStallExecutionProcessor
VOID
S2EHook_KeStallExecutionProcessor(
    /* IN */ ULONG    MicroSeconds
)
{



    UNREFERENCED_PARAMETER(MicroSeconds);



}

//RtlAppendUnicodeStringToString
NTSTATUS
S2EHook_RtlAppendUnicodeStringToString(
    /* IN */ PUNICODE_STRING    Destination,
    /* IN */ PUNICODE_STRING    Source
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlAppendUnicodeStringToString, "RtlAppendUnicodeStringToString", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlAppendUnicodeStringToString(    Destination,    Source);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlAppendUnicodeStringToString", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlAppendUnicodeStringToString(    Destination,    Source);
        S2EMessageFmt("%s returned %#x\n", "RtlAppendUnicodeStringToString", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_TOO_SMALL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlAppendUnicodeStringToString", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlCreateSecurityDescriptor
NTSTATUS
S2EHook_RtlCreateSecurityDescriptor(
    /* IN */ PSECURITY_DESCRIPTOR    SecurityDescriptor,
    /* IN */ ULONG    Revision
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlCreateSecurityDescriptor, "RtlCreateSecurityDescriptor", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlCreateSecurityDescriptor(    SecurityDescriptor,    Revision);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlCreateSecurityDescriptor", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlCreateSecurityDescriptor(    SecurityDescriptor,    Revision);
        S2EMessageFmt("%s returned %#x\n", "RtlCreateSecurityDescriptor", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_UNKNOWN_REVISION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlCreateSecurityDescriptor", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_UNKNOWN_REVISION);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwMapViewOfSection
NTSTATUS
S2EHook_ZwMapViewOfSection(
    /* IN */ HANDLE    SectionHandle,
    /* IN */ HANDLE    ProcessHandle,
    /* IN */ PVOID*    BaseAddress,
    /* IN */ ULONG    ZeroBits,
    /* IN */ ULONG    CommitSize,
    /* IN */ PLARGE_INTEGER    SectionOffset,
    /* IN */ PSIZE_T    ViewSize,
    /* IN */ SECTION_INHERIT    InheritDisposition,
    /* IN */ ULONG    AllocationType,
    /* IN */ ULONG    Protect
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwMapViewOfSection, "ZwMapViewOfSection", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwMapViewOfSection(    SectionHandle,    ProcessHandle,    BaseAddress,    ZeroBits,    CommitSize,    SectionOffset,    ViewSize,    InheritDisposition,    AllocationType,    Protect);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwMapViewOfSection", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwMapViewOfSection(    SectionHandle,    ProcessHandle,    BaseAddress,    ZeroBits,    CommitSize,    SectionOffset,    ViewSize,    InheritDisposition,    AllocationType,    Protect);
        S2EMessageFmt("%s returned %#x\n", "ZwMapViewOfSection", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PAGE_PROTECTION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwMapViewOfSection", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_INVALID_PAGE_PROTECTION,    STATUS_CONFLICTING_ADDRESSES,    STATUS_SECTION_PROTECTION);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlIntegerToUnicodeString
NTSTATUS
S2EHook_RtlIntegerToUnicodeString(
    /* IN */ ULONG    Value,
    /* IN */ ULONG    Base,
    /* IN */ PUNICODE_STRING    String
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlIntegerToUnicodeString, "RtlIntegerToUnicodeString", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlIntegerToUnicodeString(    Value,    Base,    String);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlIntegerToUnicodeString", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlIntegerToUnicodeString(    Value,    Base,    String);
        S2EMessageFmt("%s returned %#x\n", "RtlIntegerToUnicodeString", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlIntegerToUnicodeString", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_BUFFER_OVERFLOW,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ObGetObjectSecurity
NTSTATUS
S2EHook_ObGetObjectSecurity(
    /* IN */ PVOID    Object,
    /* OUT */ PSECURITY_DESCRIPTOR*    SecurityDescriptor,
    /* OUT */ PBOOLEAN    MemoryAllocated
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ObGetObjectSecurity, "ObGetObjectSecurity", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ObGetObjectSecurity(    Object,    SecurityDescriptor,    MemoryAllocated);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ObGetObjectSecurity", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ObGetObjectSecurity(    Object,    SecurityDescriptor,    MemoryAllocated);
        S2EMessageFmt("%s returned %#x\n", "ObGetObjectSecurity", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INSUFFICIENT_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ObGetObjectSecurity", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExAllocatePool
PVOID
S2EHook_ExAllocatePool(
    /* IN */ POOL_TYPE    PoolType,
    /* IN */ SIZE_T    NumberOfBytes
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExAllocatePool, "ExAllocatePool", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExAllocatePool(    PoolType,    NumberOfBytes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExAllocatePool", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExAllocatePool(    PoolType,    NumberOfBytes);
        S2EMessageFmt("%s returned %#x\n", "ExAllocatePool", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();

        if (PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE) {
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }
        return NULL;

    }
}

//IoWMIWriteEvent
NTSTATUS
S2EHook_IoWMIWriteEvent(
    /* IN */ PVOID    WnodeEventItem
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIWriteEvent, "IoWMIWriteEvent", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIWriteEvent(    WnodeEventItem);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIWriteEvent", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIWriteEvent(    WnodeEventItem);
        S2EMessageFmt("%s returned %#x\n", "IoWMIWriteEvent", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_UNSUCCESSFUL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIWriteEvent", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_UNSUCCESSFUL,    STATUS_BUFFER_OVERFLOW,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIQueryAllData
NTSTATUS
S2EHook_IoWMIQueryAllData(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ ULONG*    InOutBufferSize,
    /* OUT */ PVOID    OutBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIQueryAllData, "IoWMIQueryAllData", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIQueryAllData(    DataBlockObject,    InOutBufferSize,    OutBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIQueryAllData", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIQueryAllData(    DataBlockObject,    InOutBufferSize,    OutBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMIQueryAllData", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_GUID_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIQueryAllData", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_WMI_GUID_NOT_FOUND,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIDeviceObjectToInstanceName
NTSTATUS
S2EHook_IoWMIDeviceObjectToInstanceName(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* OUT */ PUNICODE_STRING    InstanceName
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIDeviceObjectToInstanceName, "IoWMIDeviceObjectToInstanceName", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIDeviceObjectToInstanceName(    DataBlockObject,    DeviceObject,    InstanceName);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIDeviceObjectToInstanceName", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIDeviceObjectToInstanceName(    DataBlockObject,    DeviceObject,    InstanceName);
        S2EMessageFmt("%s returned %#x\n", "IoWMIDeviceObjectToInstanceName", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_INSTANCE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIDeviceObjectToInstanceName", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_WMI_INSTANCE_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExAllocateFromPagedLookasideList
PVOID
S2EHook_ExAllocateFromPagedLookasideList(
    /* IN */ PPAGED_LOOKASIDE_LIST    Lookaside
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExAllocateFromPagedLookasideList, "ExAllocateFromPagedLookasideList", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExAllocateFromPagedLookasideList(    Lookaside);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExAllocateFromPagedLookasideList", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExAllocateFromPagedLookasideList(    Lookaside);
        S2EMessageFmt("%s returned %#x\n", "ExAllocateFromPagedLookasideList", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//IoWMISetSingleInstance
NTSTATUS
S2EHook_IoWMISetSingleInstance(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ PUNICODE_STRING    InstanceName,
    /* IN */ ULONG    Version,
    /* IN */ ULONG    ValueBufferSize,
    /* IN */ PVOID    ValueBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMISetSingleInstance, "IoWMISetSingleInstance", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMISetSingleInstance(    DataBlockObject,    InstanceName,    Version,    ValueBufferSize,    ValueBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMISetSingleInstance", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMISetSingleInstance(    DataBlockObject,    InstanceName,    Version,    ValueBufferSize,    ValueBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMISetSingleInstance", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_INSTANCE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMISetSingleInstance", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    STATUS_WMI_INSTANCE_NOT_FOUND,    STATUS_WMI_GUID_NOT_FOUND,    STATUS_WMI_SET_FAILURE,    STATUS_WMI_READ_ONLY);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIQuerySingleInstanceMultiple
NTSTATUS
S2EHook_IoWMIQuerySingleInstanceMultiple(
    /* IN */ PVOID*    DataBlockObjectList,
    /* IN */ PUNICODE_STRING    InstanceNames,
    /* IN */ ULONG    ObjectCount,
    /* IN */ ULONG*    InOutBufferSize,
    /* OUT */ PVOID    OutBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIQuerySingleInstanceMultiple, "IoWMIQuerySingleInstanceMultiple", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIQuerySingleInstanceMultiple(    DataBlockObjectList,    InstanceNames,    ObjectCount,    InOutBufferSize,    OutBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIQuerySingleInstanceMultiple", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIQuerySingleInstanceMultiple(    DataBlockObjectList,    InstanceNames,    ObjectCount,    InOutBufferSize,    OutBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMIQuerySingleInstanceMultiple", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_TOO_SMALL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIQuerySingleInstanceMultiple", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIRegistrationControl
NTSTATUS
S2EHook_IoWMIRegistrationControl(
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* IN */ ULONG    Action
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIRegistrationControl, "IoWMIRegistrationControl", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIRegistrationControl(    DeviceObject,    Action);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIRegistrationControl", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIRegistrationControl(    DeviceObject,    Action);
        S2EMessageFmt("%s returned %#x\n", "IoWMIRegistrationControl", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIRegistrationControl", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIAllocateInstanceIds
NTSTATUS
S2EHook_IoWMIAllocateInstanceIds(
    /* IN */ GUID*    Guid,
    /* IN */ ULONG    InstanceCount,
    /* OUT */ ULONG*    FirstInstanceId
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIAllocateInstanceIds, "IoWMIAllocateInstanceIds", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIAllocateInstanceIds(    Guid,    InstanceCount,    FirstInstanceId);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIAllocateInstanceIds", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIAllocateInstanceIds(    Guid,    InstanceCount,    FirstInstanceId);
        S2EMessageFmt("%s returned %#x\n", "IoWMIAllocateInstanceIds", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_UNSUCCESSFUL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIAllocateInstanceIds", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_UNSUCCESSFUL,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExAllocatePoolWithTag
PVOID
S2EHook_ExAllocatePoolWithTag(
    /* IN */ POOL_TYPE    PoolType,
    /* IN */ SIZE_T    NumberOfBytes,
    /* IN */ ULONG    Tag
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExAllocatePoolWithTag, "ExAllocatePoolWithTag", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExAllocatePoolWithTag(    PoolType,    NumberOfBytes,    Tag);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExAllocatePoolWithTag", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExAllocatePoolWithTag(    PoolType,    NumberOfBytes,    Tag);
        S2EMessageFmt("%s returned %#x\n", "ExAllocatePoolWithTag", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();

        if (PoolType & POOL_RAISE_IF_ALLOCATION_FAILURE) {
            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        }
        return NULL;

    }
}

//PsRemoveLoadImageNotifyRoutine
NTSTATUS
S2EHook_PsRemoveLoadImageNotifyRoutine(
    /* IN */ PLOAD_IMAGE_NOTIFY_ROUTINE    NotifyRoutine
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PsRemoveLoadImageNotifyRoutine, "PsRemoveLoadImageNotifyRoutine", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PsRemoveLoadImageNotifyRoutine(    NotifyRoutine);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PsRemoveLoadImageNotifyRoutine", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PsRemoveLoadImageNotifyRoutine(    NotifyRoutine);
        S2EMessageFmt("%s returned %#x\n", "PsRemoveLoadImageNotifyRoutine", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_PROCEDURE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_PsRemoveLoadImageNotifyRoutine", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_PROCEDURE_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoReportResourceForDetection
NTSTATUS
S2EHook_IoReportResourceForDetection(
    /* IN */ PDRIVER_OBJECT    DriverObject,
    /* IN */ PCM_RESOURCE_LIST    DriverList,
    /* IN */ ULONG    DriverListSize,
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* IN */ PCM_RESOURCE_LIST    DeviceList,
    /* IN */ ULONG    DeviceListSize,
    /* OUT */ PBOOLEAN    ConflictDetected
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoReportResourceForDetection, "IoReportResourceForDetection", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoReportResourceForDetection(    DriverObject,    DriverList,    DriverListSize,    DeviceObject,    DeviceList,    DeviceListSize,    ConflictDetected);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoReportResourceForDetection", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoReportResourceForDetection(    DriverObject,    DriverList,    DriverListSize,    DeviceObject,    DeviceList,    DeviceListSize,    ConflictDetected);
        S2EMessageFmt("%s returned %#x\n", "IoReportResourceForDetection", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_UNSUCCESSFUL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoReportResourceForDetection", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_UNSUCCESSFUL,    STATUS_CONFLICTING_ADDRESSES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmAllocateNonCachedMemory
PVOID
S2EHook_MmAllocateNonCachedMemory(
    /* IN */ ULONG    NumberOfBytes
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmAllocateNonCachedMemory, "MmAllocateNonCachedMemory", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmAllocateNonCachedMemory(    NumberOfBytes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmAllocateNonCachedMemory", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmAllocateNonCachedMemory(    NumberOfBytes);
        S2EMessageFmt("%s returned %#x\n", "MmAllocateNonCachedMemory", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//ZwEnumerateKey
NTSTATUS
S2EHook_ZwEnumerateKey(
    /* IN */ HANDLE    KeyHandle,
    /* IN */ ULONG    Index,
    /* IN */ KEY_INFORMATION_CLASS    KeyInformationClass,
    /* OUT */ PVOID    KeyInformation,
    /* IN */ ULONG    Length,
    /* OUT */ PULONG    ResultLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwEnumerateKey, "ZwEnumerateKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwEnumerateKey(    KeyHandle,    Index,    KeyInformationClass,    KeyInformation,    Length,    ResultLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwEnumerateKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwEnumerateKey(    KeyHandle,    Index,    KeyInformationClass,    KeyInformation,    Length,    ResultLength);
        S2EMessageFmt("%s returned %#x\n", "ZwEnumerateKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwEnumerateKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    STATUS_BUFFER_OVERFLOW,    STATUS_NO_MORE_ENTRIES,    STATUS_INVALID_PARAMETER,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoConnectInterrupt
NTSTATUS
S2EHook_IoConnectInterrupt(
    /* OUT */ PKINTERRUPT*    InterruptObject,
    /* IN */ PKSERVICE_ROUTINE    ServiceRoutine,
    /* IN */ PVOID    ServiceContext,
    /* IN */ PKSPIN_LOCK    SpinLock,
    /* IN */ ULONG    Vector,
    /* IN */ KIRQL    Irql,
    /* IN */ KIRQL    SynchronizeIrql,
    /* IN */ KINTERRUPT_MODE    InterruptMode,
    /* IN */ BOOLEAN    ShareVector,
    /* IN */ KAFFINITY    ProcessorEnableMask,
    /* IN */ BOOLEAN    FloatingSave
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoConnectInterrupt, "IoConnectInterrupt", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoConnectInterrupt(    InterruptObject,    ServiceRoutine,    ServiceContext,    SpinLock,    Vector,    Irql,    SynchronizeIrql,    InterruptMode,    ShareVector,    ProcessorEnableMask,    FloatingSave);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoConnectInterrupt", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoConnectInterrupt(    InterruptObject,    ServiceRoutine,    ServiceContext,    SpinLock,    Vector,    Irql,    SynchronizeIrql,    InterruptMode,    ShareVector,    ProcessorEnableMask,    FloatingSave);
        S2EMessageFmt("%s returned %#x\n", "IoConnectInterrupt", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoConnectInterrupt", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_PARAMETER,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoAttachDevice
NTSTATUS
S2EHook_IoAttachDevice(
    /* IN */ PDEVICE_OBJECT    SourceDevice,
    /* IN */ PUNICODE_STRING    TargetDevice,
    /* OUT */ PDEVICE_OBJECT*    AttachedDevice
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoAttachDevice, "IoAttachDevice", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoAttachDevice(    SourceDevice,    TargetDevice,    AttachedDevice);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoAttachDevice", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoAttachDevice(    SourceDevice,    TargetDevice,    AttachedDevice);
        S2EMessageFmt("%s returned %#x\n", "IoAttachDevice", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_TYPE_MISMATCH, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoAttachDevice", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    STATUS_OBJECT_TYPE_MISMATCH,    STATUS_OBJECT_NAME_INVALID,    STATUS_INVALID_PARAMETER,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwQuerySymbolicLinkObject
NTSTATUS
S2EHook_ZwQuerySymbolicLinkObject(
    /* IN */ HANDLE    LinkHandle,
    /* IN */ PUNICODE_STRING    LinkTarget,
    /* OUT */ PULONG    ReturnedLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwQuerySymbolicLinkObject, "ZwQuerySymbolicLinkObject", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwQuerySymbolicLinkObject(    LinkHandle,    LinkTarget,    ReturnedLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwQuerySymbolicLinkObject", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwQuerySymbolicLinkObject(    LinkHandle,    LinkTarget,    ReturnedLength);
        S2EMessageFmt("%s returned %#x\n", "ZwQuerySymbolicLinkObject", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_TOO_SMALL, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwQuerySymbolicLinkObject", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMISetSingleItem
NTSTATUS
S2EHook_IoWMISetSingleItem(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ PUNICODE_STRING    InstanceName,
    /* IN */ ULONG    DataItemId,
    /* IN */ ULONG    Version,
    /* IN */ ULONG    ValueBufferSize,
    /* IN */ PVOID    ValueBuffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMISetSingleItem, "IoWMISetSingleItem", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMISetSingleItem(    DataBlockObject,    InstanceName,    DataItemId,    Version,    ValueBufferSize,    ValueBuffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMISetSingleItem", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMISetSingleItem(    DataBlockObject,    InstanceName,    DataItemId,    Version,    ValueBufferSize,    ValueBuffer);
        S2EMessageFmt("%s returned %#x\n", "IoWMISetSingleItem", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_GUID_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMISetSingleItem", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 5,    STATUS_WMI_GUID_NOT_FOUND,    STATUS_WMI_INSTANCE_NOT_FOUND,    STATUS_WMI_ITEMID_NOT_FOUND,    STATUS_WMI_SET_FAILURE,    STATUS_WMI_READ_ONLY);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwSetInformationThread
NTSTATUS
S2EHook_ZwSetInformationThread(
    /* IN */ HANDLE    ThreadHandle,
    /* IN */ THREADINFOCLASS    ThreadInformationClass,
    /* IN */ PVOID    ThreadInformation,
    /* IN */ ULONG    ThreadInformationLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwSetInformationThread, "ZwSetInformationThread", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwSetInformationThread(    ThreadHandle,    ThreadInformationClass,    ThreadInformation,    ThreadInformationLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwSetInformationThread", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwSetInformationThread(    ThreadHandle,    ThreadInformationClass,    ThreadInformation,    ThreadInformationLength);
        S2EMessageFmt("%s returned %#x\n", "ZwSetInformationThread", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INFO_LENGTH_MISMATCH, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwSetInformationThread", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INFO_LENGTH_MISMATCH,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//WmiTraceMessage
NTSTATUS
S2EHook_WmiTraceMessage(
    /* IN */ TRACEHANDLE    LoggerHandle,
    /* IN */ ULONG    MessageFlags,
    /* IN */ LPGUID    MessageGuid,
    /* IN */ USHORT    MessageNumber, ...
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&WmiTraceMessage, "WmiTraceMessage", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = WmiTraceMessage(    LoggerHandle,    MessageFlags,    MessageGuid,    MessageNumber);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_WmiTraceMessage", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = WmiTraceMessage(    LoggerHandle,    MessageFlags,    MessageGuid,    MessageNumber);
        S2EMessageFmt("%s returned %#x\n", "WmiTraceMessage", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_WmiTraceMessage", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_HANDLE,    STATUS_NO_MEMORY);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoGetDeviceInterfaceAlias
NTSTATUS
S2EHook_IoGetDeviceInterfaceAlias(
    /* IN */ PUNICODE_STRING    SymbolicLinkName,
    /* IN */ GUID*    AliasInterfaceClassGuid,
    /* OUT */ PUNICODE_STRING    AliasSymbolicLinkName
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoGetDeviceInterfaceAlias, "IoGetDeviceInterfaceAlias", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoGetDeviceInterfaceAlias(    SymbolicLinkName,    AliasInterfaceClassGuid,    AliasSymbolicLinkName);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoGetDeviceInterfaceAlias", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoGetDeviceInterfaceAlias(    SymbolicLinkName,    AliasInterfaceClassGuid,    AliasSymbolicLinkName);
        S2EMessageFmt("%s returned %#x\n", "IoGetDeviceInterfaceAlias", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoGetDeviceInterfaceAlias", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_OBJECT_NAME_NOT_FOUND,    STATUS_INVALID_HANDLE,    STATUS_OBJECT_PATH_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoOpenDeviceRegistryKey
NTSTATUS
S2EHook_IoOpenDeviceRegistryKey(
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* IN */ ULONG    DevInstKeyType,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* OUT */ PHANDLE    DevInstRegKey
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoOpenDeviceRegistryKey, "IoOpenDeviceRegistryKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoOpenDeviceRegistryKey(    DeviceObject,    DevInstKeyType,    DesiredAccess,    DevInstRegKey);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoOpenDeviceRegistryKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoOpenDeviceRegistryKey(    DeviceObject,    DevInstKeyType,    DesiredAccess,    DevInstRegKey);
        S2EMessageFmt("%s returned %#x\n", "IoOpenDeviceRegistryKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_DEVICE_REQUEST, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoOpenDeviceRegistryKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_DEVICE_REQUEST,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoCheckShareAccess
NTSTATUS
S2EHook_IoCheckShareAccess(
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ ULONG    DesiredShareAccess,
    /* IN */ PFILE_OBJECT    FileObject,
    /* IN */ PSHARE_ACCESS    ShareAccess,
    /* IN */ BOOLEAN    Update
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoCheckShareAccess, "IoCheckShareAccess", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoCheckShareAccess(    DesiredAccess,    DesiredShareAccess,    FileObject,    ShareAccess,    Update);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoCheckShareAccess", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoCheckShareAccess(    DesiredAccess,    DesiredShareAccess,    FileObject,    ShareAccess,    Update);
        S2EMessageFmt("%s returned %#x\n", "IoCheckShareAccess", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_SHARING_VIOLATION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoCheckShareAccess", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_SHARING_VIOLATION);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//DbgPrintEx
ULONG
S2EHook_DbgPrintEx(
    /*  */ ULONG    ComponentId,
    /*  */ ULONG    Level,
    /*  */ PCH    Format, ...
)
{



    S2EMessageFmt("DbgPrintEx %s\n", Format);

    return STATUS_SUCCESS;



}

//PsSetLoadImageNotifyRoutine
NTSTATUS
S2EHook_PsSetLoadImageNotifyRoutine(
    /* IN */ PLOAD_IMAGE_NOTIFY_ROUTINE    NotifyRoutine
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&PsSetLoadImageNotifyRoutine, "PsSetLoadImageNotifyRoutine", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = PsSetLoadImageNotifyRoutine(    NotifyRoutine);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_PsSetLoadImageNotifyRoutine", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = PsSetLoadImageNotifyRoutine(    NotifyRoutine);
        S2EMessageFmt("%s returned %#x\n", "PsSetLoadImageNotifyRoutine", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INSUFFICIENT_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_PsSetLoadImageNotifyRoutine", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmAllocateMappingAddress
PVOID
S2EHook_MmAllocateMappingAddress(
    /* IN */ SIZE_T    NumberOfBytes,
    /* IN */ ULONG    PoolTag
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmAllocateMappingAddress, "MmAllocateMappingAddress", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmAllocateMappingAddress(    NumberOfBytes,    PoolTag);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmAllocateMappingAddress", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmAllocateMappingAddress(    NumberOfBytes,    PoolTag);
        S2EMessageFmt("%s returned %#x\n", "MmAllocateMappingAddress", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//IoCreateDevice
NTSTATUS
S2EHook_IoCreateDevice(
    /* IN */ PDRIVER_OBJECT    DriverObject,
    /* IN */ ULONG    DeviceExtensionSize,
    /* IN */ PUNICODE_STRING    DeviceName,
    /* IN */ ULONG    DeviceType,
    /* IN */ ULONG    DeviceCharacteristics,
    /* IN */ BOOLEAN    Exclusive,
    /* OUT */ PDEVICE_OBJECT*    DeviceObject
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoCreateDevice, "IoCreateDevice", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoCreateDevice(    DriverObject,    DeviceExtensionSize,    DeviceName,    DeviceType,    DeviceCharacteristics,    Exclusive,    DeviceObject);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoCreateDevice", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoCreateDevice(    DriverObject,    DeviceExtensionSize,    DeviceName,    DeviceType,    DeviceCharacteristics,    Exclusive,    DeviceObject);
        S2EMessageFmt("%s returned %#x\n", "IoCreateDevice", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_COLLISION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoCreateDevice", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_OBJECT_NAME_COLLISION,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwDeleteKey
NTSTATUS
S2EHook_ZwDeleteKey(
    /* IN */ HANDLE    KeyHandle
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwDeleteKey, "ZwDeleteKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwDeleteKey(    KeyHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwDeleteKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwDeleteKey(    KeyHandle);
        S2EMessageFmt("%s returned %#x\n", "ZwDeleteKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwDeleteKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoVerifyPartitionTable
NTSTATUS
S2EHook_IoVerifyPartitionTable(
    /* IN */ PDEVICE_OBJECT    DeviceObject,
    /* IN */ BOOLEAN    FixErrors
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoVerifyPartitionTable, "IoVerifyPartitionTable", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoVerifyPartitionTable(    DeviceObject,    FixErrors);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoVerifyPartitionTable", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoVerifyPartitionTable(    DeviceObject,    FixErrors);
        S2EMessageFmt("%s returned %#x\n", "IoVerifyPartitionTable", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_DISK_CORRUPT_ERROR, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoVerifyPartitionTable", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_DISK_CORRUPT_ERROR);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmCreateMdl
PMDL
S2EHook_MmCreateMdl(
    /* IN */ PMDL    MemoryDescriptorList,
    /* IN */ PVOID    Base,
    /* IN */ SIZE_T    Length
)
{

    /* Variable declarations */PMDL RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmCreateMdl, "MmCreateMdl", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmCreateMdl(    MemoryDescriptorList,    Base,    Length);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmCreateMdl", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmCreateMdl(    MemoryDescriptorList,    Base,    Length);
        S2EMessageFmt("%s returned %#x\n", "MmCreateMdl", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//ZwSetEvent
NTSTATUS
S2EHook_ZwSetEvent(
    /* IN */ HANDLE    EventHandle,
    /* OUT */ PLONG    NumberOfThreadsReleased
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwSetEvent, "ZwSetEvent", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwSetEvent(    EventHandle,    NumberOfThreadsReleased);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwSetEvent", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwSetEvent(    EventHandle,    NumberOfThreadsReleased);
        S2EMessageFmt("%s returned %#x\n", "ZwSetEvent", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_HANDLE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwSetEvent", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_INVALID_HANDLE,    STATUS_ACCESS_DENIED,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ExUuidCreate
NTSTATUS
S2EHook_ExUuidCreate(
    /* OUT */ UUID*    Uuid
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ExUuidCreate, "ExUuidCreate", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ExUuidCreate(    Uuid);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ExUuidCreate", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ExUuidCreate(    Uuid);
        S2EMessageFmt("%s returned %#x\n", "ExUuidCreate", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_RETRY, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ExUuidCreate", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_RETRY);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwQueryKey
NTSTATUS
S2EHook_ZwQueryKey(
    /* IN */ HANDLE    KeyHandle,
    /* IN */ KEY_INFORMATION_CLASS    KeyInformationClass,
    /* OUT */ PVOID    KeyInformation,
    /* IN */ ULONG    Length,
    /* OUT */ PULONG    ResultLength
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwQueryKey, "ZwQueryKey", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwQueryKey(    KeyHandle,    KeyInformationClass,    KeyInformation,    Length,    ResultLength);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwQueryKey", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwQueryKey(    KeyHandle,    KeyInformationClass,    KeyInformation,    Length,    ResultLength);
        S2EMessageFmt("%s returned %#x\n", "ZwQueryKey", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwQueryKey", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_BUFFER_OVERFLOW,    STATUS_INVALID_PARAMETER,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlHashUnicodeString
NTSTATUS
S2EHook_RtlHashUnicodeString(
    /* IN */ UNICODE_STRING*    String,
    /* IN */ BOOLEAN    CaseInSensitive,
    /* IN */ ULONG    HashAlgorithm,
    /* OUT */ PULONG    HashValue
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlHashUnicodeString, "RtlHashUnicodeString", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlHashUnicodeString(    String,    CaseInSensitive,    HashAlgorithm,    HashValue);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlHashUnicodeString", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlHashUnicodeString(    String,    CaseInSensitive,    HashAlgorithm,    HashValue);
        S2EMessageFmt("%s returned %#x\n", "RtlHashUnicodeString", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlHashUnicodeString", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//KeSaveFloatingPointState
NTSTATUS
S2EHook_KeSaveFloatingPointState(
    /* OUT */ PKFLOATING_SAVE    FloatSave
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&KeSaveFloatingPointState, "KeSaveFloatingPointState", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = KeSaveFloatingPointState(    FloatSave);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_KeSaveFloatingPointState", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = KeSaveFloatingPointState(    FloatSave);
        S2EMessageFmt("%s returned %#x\n", "KeSaveFloatingPointState", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_ILLEGAL_FLOAT_CONTEXT, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_KeSaveFloatingPointState", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    STATUS_ILLEGAL_FLOAT_CONTEXT,    STATUS_INSUFFICIENT_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoAllocateErrorLogEntry
PVOID
S2EHook_IoAllocateErrorLogEntry(
    /* IN */ PVOID    IoObject,
    /* IN */ UCHAR    EntrySize
)
{

    /* Variable declarations */PVOID RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoAllocateErrorLogEntry, "IoAllocateErrorLogEntry", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoAllocateErrorLogEntry(    IoObject,    EntrySize);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoAllocateErrorLogEntry", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoAllocateErrorLogEntry(    IoObject,    EntrySize);
        S2EMessageFmt("%s returned %#x\n", "IoAllocateErrorLogEntry", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//IoAllocateWorkItem
PIO_WORKITEM
S2EHook_IoAllocateWorkItem(
    /* IN */ PDEVICE_OBJECT    DeviceObject
)
{

    /* Variable declarations */PIO_WORKITEM RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoAllocateWorkItem, "IoAllocateWorkItem", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoAllocateWorkItem(    DeviceObject);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoAllocateWorkItem", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoAllocateWorkItem(    DeviceObject);
        S2EMessageFmt("%s returned %#x\n", "IoAllocateWorkItem", RetVal);
        return RetVal;
    } else {
        S2EIncrementFaultCount();
        return NULL;
    }
}

//WmiQueryTraceInformation
NTSTATUS
S2EHook_WmiQueryTraceInformation(
    /* IN */ TRACE_INFORMATION_CLASS    TraceInformationClass,
    /* OUT */ PVOID    TraceInformation,
    /* IN */ ULONG    TraceInformationLength,
    /* OUT */ PULONG    RequiredLength,
    /* IN */ PVOID    Buffer
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&WmiQueryTraceInformation, "WmiQueryTraceInformation", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = WmiQueryTraceInformation(    TraceInformationClass,    TraceInformation,    TraceInformationLength,    RequiredLength,    Buffer);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_WmiQueryTraceInformation", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = WmiQueryTraceInformation(    TraceInformationClass,    TraceInformation,    TraceInformationLength,    RequiredLength,    Buffer);
        S2EMessageFmt("%s returned %#x\n", "WmiQueryTraceInformation", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INFO_LENGTH_MISMATCH, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_WmiQueryTraceInformation", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 6,    STATUS_INFO_LENGTH_MISMATCH,    STATUS_INVALID_PARAMETER,    STATUS_INVALID_PARAMETER_MIX,    STATUS_INVALID_HANDLE,    STATUS_NOT_FOUND,    STATUS_INVALID_INFO_CLASS);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoReportTargetDeviceChange
NTSTATUS
S2EHook_IoReportTargetDeviceChange(
    /* IN */ PDEVICE_OBJECT    PhysicalDeviceObject,
    /* IN */ PVOID    NotificationStructure
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoReportTargetDeviceChange, "IoReportTargetDeviceChange", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoReportTargetDeviceChange(    PhysicalDeviceObject,    NotificationStructure);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoReportTargetDeviceChange", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoReportTargetDeviceChange(    PhysicalDeviceObject,    NotificationStructure);
        S2EMessageFmt("%s returned %#x\n", "IoReportTargetDeviceChange", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_DEVICE_REQUEST, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoReportTargetDeviceChange", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_DEVICE_REQUEST);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoRegisterDeviceInterface
NTSTATUS
S2EHook_IoRegisterDeviceInterface(
    /* IN */ PDEVICE_OBJECT    PhysicalDeviceObject,
    /* IN */ GUID*    InterfaceClassGuid,
    /* IN */ PUNICODE_STRING    ReferenceString,
    /* OUT */ PUNICODE_STRING    SymbolicLinkName
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoRegisterDeviceInterface, "IoRegisterDeviceInterface", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoRegisterDeviceInterface(    PhysicalDeviceObject,    InterfaceClassGuid,    ReferenceString,    SymbolicLinkName);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoRegisterDeviceInterface", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoRegisterDeviceInterface(    PhysicalDeviceObject,    InterfaceClassGuid,    ReferenceString,    SymbolicLinkName);
        S2EMessageFmt("%s returned %#x\n", "IoRegisterDeviceInterface", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_DEVICE_REQUEST, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoRegisterDeviceInterface", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_DEVICE_REQUEST);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//RtlQueryRegistryValues
NTSTATUS
S2EHook_RtlQueryRegistryValues(
    /* IN */ ULONG    RelativeTo,
    /* IN */ PCWSTR    Path,
    /* IN */ PRTL_QUERY_REGISTRY_TABLE    QueryTable,
    /* IN */ PVOID    Context,
    /* IN */ PVOID    Environment
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&RtlQueryRegistryValues, "RtlQueryRegistryValues", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = RtlQueryRegistryValues(    RelativeTo,    Path,    QueryTable,    Context,    Environment);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_RtlQueryRegistryValues", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = RtlQueryRegistryValues(    RelativeTo,    Path,    QueryTable,    Context,    Environment);
        S2EMessageFmt("%s returned %#x\n", "RtlQueryRegistryValues", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_OBJECT_NAME_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_RtlQueryRegistryValues", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_OBJECT_NAME_NOT_FOUND,    STATUS_INVALID_PARAMETER,    STATUS_BUFFER_TOO_SMALL);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//MmAdvanceMdl
NTSTATUS
S2EHook_MmAdvanceMdl(
    /* IN */ PMDL    Mdl,
    /* IN */ ULONG    NumberOfBytes
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&MmAdvanceMdl, "MmAdvanceMdl", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = MmAdvanceMdl(    Mdl,    NumberOfBytes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_MmAdvanceMdl", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = MmAdvanceMdl(    Mdl,    NumberOfBytes);
        S2EMessageFmt("%s returned %#x\n", "MmAdvanceMdl", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_INVALID_PARAMETER_2, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_MmAdvanceMdl", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_INVALID_PARAMETER_2);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//IoWMIHandleToInstanceName
NTSTATUS
S2EHook_IoWMIHandleToInstanceName(
    /* IN */ PVOID    DataBlockObject,
    /* IN */ HANDLE    FileHandle,
    /* OUT */ PUNICODE_STRING    InstanceName
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&IoWMIHandleToInstanceName, "IoWMIHandleToInstanceName", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = IoWMIHandleToInstanceName(    DataBlockObject,    FileHandle,    InstanceName);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_IoWMIHandleToInstanceName", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = IoWMIHandleToInstanceName(    DataBlockObject,    FileHandle,    InstanceName);
        S2EMessageFmt("%s returned %#x\n", "IoWMIHandleToInstanceName", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_WMI_INSTANCE_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_IoWMIHandleToInstanceName", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_WMI_INSTANCE_NOT_FOUND);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwUnmapViewOfSection
NTSTATUS
S2EHook_ZwUnmapViewOfSection(
    /* IN */ HANDLE    ProcessHandle,
    /* IN */ PVOID    BaseAddress
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwUnmapViewOfSection, "ZwUnmapViewOfSection", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwUnmapViewOfSection(    ProcessHandle,    BaseAddress);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwUnmapViewOfSection", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwUnmapViewOfSection(    ProcessHandle,    BaseAddress);
        S2EMessageFmt("%s returned %#x\n", "ZwUnmapViewOfSection", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_ACCESS_DENIED, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwUnmapViewOfSection", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//ZwCreateDirectoryObject
NTSTATUS
S2EHook_ZwCreateDirectoryObject(
    /* OUT */ PHANDLE    DirectoryHandle,
    /* IN */ ACCESS_MASK    DesiredAccess,
    /* IN */ POBJECT_ATTRIBUTES    ObjectAttributes
)
{

    /* Variable declarations */NTSTATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&ZwCreateDirectoryObject, "ZwCreateDirectoryObject", "ntoskrnl.exe", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = ZwCreateDirectoryObject(    DirectoryHandle,    DesiredAccess,    ObjectAttributes);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_ZwCreateDirectoryObject", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = ZwCreateDirectoryObject(    DirectoryHandle,    DesiredAccess,    ObjectAttributes);
        S2EMessageFmt("%s returned %#x\n", "ZwCreateDirectoryObject", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = STATUS_ACCESS_VIOLATION, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_ZwCreateDirectoryObject", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    STATUS_ACCESS_VIOLATION,    STATUS_DATATYPE_MISALIGNMENT,    STATUS_ACCESS_DENIED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

/* 102 hooks */
const S2E_HOOK g_NtoskrnlHooks[] = {

    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "CmUnRegisterCallback", (UINT_PTR) S2EHook_CmUnRegisterCallback},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "DbgPrint", (UINT_PTR) S2EHook_DbgPrint},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "DbgPrintEx", (UINT_PTR) S2EHook_DbgPrintEx},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExAllocateFromPagedLookasideList", (UINT_PTR) S2EHook_ExAllocateFromPagedLookasideList},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExAllocatePool", (UINT_PTR) S2EHook_ExAllocatePool},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExAllocatePoolWithQuota", (UINT_PTR) S2EHook_ExAllocatePoolWithQuota},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExAllocatePoolWithQuotaTag", (UINT_PTR) S2EHook_ExAllocatePoolWithQuotaTag},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExAllocatePoolWithTag", (UINT_PTR) S2EHook_ExAllocatePoolWithTag},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExAllocatePoolWithTagPriority", (UINT_PTR) S2EHook_ExAllocatePoolWithTagPriority},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExRegisterCallback", (UINT_PTR) S2EHook_ExRegisterCallback},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ExUuidCreate", (UINT_PTR) S2EHook_ExUuidCreate}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoAllocateDriverObjectExtension", (UINT_PTR) S2EHook_IoAllocateDriverObjectExtension}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoAllocateErrorLogEntry", (UINT_PTR) S2EHook_IoAllocateErrorLogEntry},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoAllocateIrp", (UINT_PTR) S2EHook_IoAllocateIrp},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoAllocateMdl", (UINT_PTR) S2EHook_IoAllocateMdl},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoAllocateWorkItem", (UINT_PTR) S2EHook_IoAllocateWorkItem},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoAttachDevice", (UINT_PTR) S2EHook_IoAttachDevice}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoCheckShareAccess", (UINT_PTR) S2EHook_IoCheckShareAccess},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoConnectInterrupt", (UINT_PTR) S2EHook_IoConnectInterrupt}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoCreateDevice", (UINT_PTR) S2EHook_IoCreateDevice}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoGetBootDiskInformation", (UINT_PTR) S2EHook_IoGetBootDiskInformation},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoGetDeviceInterfaceAlias", (UINT_PTR) S2EHook_IoGetDeviceInterfaceAlias}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoGetDeviceInterfaces", (UINT_PTR) S2EHook_IoGetDeviceInterfaces}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoGetDeviceObjectPointer", (UINT_PTR) S2EHook_IoGetDeviceObjectPointer}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoGetDeviceProperty", (UINT_PTR) S2EHook_IoGetDeviceProperty}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoOpenDeviceInterfaceRegistryKey", (UINT_PTR) S2EHook_IoOpenDeviceInterfaceRegistryKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoOpenDeviceRegistryKey", (UINT_PTR) S2EHook_IoOpenDeviceRegistryKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoRegisterDeviceInterface", (UINT_PTR) S2EHook_IoRegisterDeviceInterface}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoReportResourceForDetection", (UINT_PTR) S2EHook_IoReportResourceForDetection}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoReportTargetDeviceChange", (UINT_PTR) S2EHook_IoReportTargetDeviceChange},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoReportTargetDeviceChangeAsynchronous", (UINT_PTR) S2EHook_IoReportTargetDeviceChangeAsynchronous},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoSetDeviceInterfaceState", (UINT_PTR) S2EHook_IoSetDeviceInterfaceState},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoVerifyPartitionTable", (UINT_PTR) S2EHook_IoVerifyPartitionTable},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIAllocateInstanceIds", (UINT_PTR) S2EHook_IoWMIAllocateInstanceIds}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIDeviceObjectToInstanceName", (UINT_PTR) S2EHook_IoWMIDeviceObjectToInstanceName}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIExecuteMethod", (UINT_PTR) S2EHook_IoWMIExecuteMethod},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIHandleToInstanceName", (UINT_PTR) S2EHook_IoWMIHandleToInstanceName}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIQueryAllData", (UINT_PTR) S2EHook_IoWMIQueryAllData}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIQueryAllDataMultiple", (UINT_PTR) S2EHook_IoWMIQueryAllDataMultiple}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIQuerySingleInstance", (UINT_PTR) S2EHook_IoWMIQuerySingleInstance}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIQuerySingleInstanceMultiple", (UINT_PTR) S2EHook_IoWMIQuerySingleInstanceMultiple}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIRegistrationControl", (UINT_PTR) S2EHook_IoWMIRegistrationControl},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMISetSingleInstance", (UINT_PTR) S2EHook_IoWMISetSingleInstance},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMISetSingleItem", (UINT_PTR) S2EHook_IoWMISetSingleItem},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMISuggestInstanceName", (UINT_PTR) S2EHook_IoWMISuggestInstanceName}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "IoWMIWriteEvent", (UINT_PTR) S2EHook_IoWMIWriteEvent},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "KeSaveFloatingPointState", (UINT_PTR) S2EHook_KeSaveFloatingPointState}, /* multiple outputs */
    {(UINT_PTR) "hal.dll", (UINT_PTR) "KeStallExecutionProcessor", (UINT_PTR) S2EHook_KeStallExecutionProcessor},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmAdvanceMdl", (UINT_PTR) S2EHook_MmAdvanceMdl},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmAllocateContiguousMemory", (UINT_PTR) S2EHook_MmAllocateContiguousMemory},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmAllocateContiguousMemorySpecifyCache", (UINT_PTR) S2EHook_MmAllocateContiguousMemorySpecifyCache},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmAllocateMappingAddress", (UINT_PTR) S2EHook_MmAllocateMappingAddress},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmAllocateNonCachedMemory", (UINT_PTR) S2EHook_MmAllocateNonCachedMemory},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmAllocatePagesForMdl", (UINT_PTR) S2EHook_MmAllocatePagesForMdl},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmCreateMdl", (UINT_PTR) S2EHook_MmCreateMdl},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmMapIoSpace", (UINT_PTR) S2EHook_MmMapIoSpace},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "MmProtectMdlSystemAddress", (UINT_PTR) S2EHook_MmProtectMdlSystemAddress},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ObGetObjectSecurity", (UINT_PTR) S2EHook_ObGetObjectSecurity}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ObReferenceObjectByHandle", (UINT_PTR) S2EHook_ObReferenceObjectByHandle}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ObReferenceObjectByPointer", (UINT_PTR) S2EHook_ObReferenceObjectByPointer},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PoRegisterSystemState", (UINT_PTR) S2EHook_PoRegisterSystemState},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PoRequestPowerIrp", (UINT_PTR) S2EHook_PoRequestPowerIrp}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PsRemoveCreateThreadNotifyRoutine", (UINT_PTR) S2EHook_PsRemoveCreateThreadNotifyRoutine},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PsRemoveLoadImageNotifyRoutine", (UINT_PTR) S2EHook_PsRemoveLoadImageNotifyRoutine},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PsSetCreateProcessNotifyRoutine", (UINT_PTR) S2EHook_PsSetCreateProcessNotifyRoutine},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PsSetCreateThreadNotifyRoutine", (UINT_PTR) S2EHook_PsSetCreateThreadNotifyRoutine},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "PsSetLoadImageNotifyRoutine", (UINT_PTR) S2EHook_PsSetLoadImageNotifyRoutine},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlAppendUnicodeStringToString", (UINT_PTR) S2EHook_RtlAppendUnicodeStringToString},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlAppendUnicodeToString", (UINT_PTR) S2EHook_RtlAppendUnicodeToString},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlCharToInteger", (UINT_PTR) S2EHook_RtlCharToInteger},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlCreateSecurityDescriptor", (UINT_PTR) S2EHook_RtlCreateSecurityDescriptor},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlHashUnicodeString", (UINT_PTR) S2EHook_RtlHashUnicodeString}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlInt64ToUnicodeString", (UINT_PTR) S2EHook_RtlInt64ToUnicodeString},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlIntegerToUnicodeString", (UINT_PTR) S2EHook_RtlIntegerToUnicodeString},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlQueryRegistryValues", (UINT_PTR) S2EHook_RtlQueryRegistryValues},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlSetDaclSecurityDescriptor", (UINT_PTR) S2EHook_RtlSetDaclSecurityDescriptor},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlUnicodeStringToInteger", (UINT_PTR) S2EHook_RtlUnicodeStringToInteger}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "RtlVerifyVersionInfo", (UINT_PTR) S2EHook_RtlVerifyVersionInfo},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "SeAssignSecurity", (UINT_PTR) S2EHook_SeAssignSecurity}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "SeAssignSecurityEx", (UINT_PTR) S2EHook_SeAssignSecurityEx}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "WmiQueryTraceInformation", (UINT_PTR) S2EHook_WmiQueryTraceInformation}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "WmiTraceMessage", (UINT_PTR) S2EHook_WmiTraceMessage},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwClose", (UINT_PTR) S2EHook_ZwClose},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwCreateDirectoryObject", (UINT_PTR) S2EHook_ZwCreateDirectoryObject}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwCreateEvent", (UINT_PTR) S2EHook_ZwCreateEvent}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwCreateFile", (UINT_PTR) S2EHook_ZwCreateFile}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwDeleteKey", (UINT_PTR) S2EHook_ZwDeleteKey},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwDeleteValueKey", (UINT_PTR) S2EHook_ZwDeleteValueKey},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwDeviceIoControlFile", (UINT_PTR) S2EHook_ZwDeviceIoControlFile}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwEnumerateKey", (UINT_PTR) S2EHook_ZwEnumerateKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwEnumerateValueKey", (UINT_PTR) S2EHook_ZwEnumerateValueKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwMapViewOfSection", (UINT_PTR) S2EHook_ZwMapViewOfSection},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwOpenKey", (UINT_PTR) S2EHook_ZwOpenKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwOpenSection", (UINT_PTR) S2EHook_ZwOpenSection}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwQueryKey", (UINT_PTR) S2EHook_ZwQueryKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwQuerySymbolicLinkObject", (UINT_PTR) S2EHook_ZwQuerySymbolicLinkObject}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwQueryValueKey", (UINT_PTR) S2EHook_ZwQueryValueKey}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwSetEvent", (UINT_PTR) S2EHook_ZwSetEvent}, /* multiple outputs */
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwSetInformationThread", (UINT_PTR) S2EHook_ZwSetInformationThread},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwSetValueKey", (UINT_PTR) S2EHook_ZwSetValueKey},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwUnmapViewOfSection", (UINT_PTR) S2EHook_ZwUnmapViewOfSection},
    {(UINT_PTR) "ntoskrnl.exe", (UINT_PTR) "ZwWaitForSingleObject", (UINT_PTR) S2EHook_ZwWaitForSingleObject},
    {0,0,0}

};

/**

 * 61 functions that have one status and other output arguments:
 * -------------------------------------------
 * CmRegisterCallback [IN=2 OUT=1]
 * ExCreateCallback [IN=3 OUT=1]
 * ExUuidCreate [IN=0 OUT=1]
 * IoAllocateDriverObjectExtension [IN=3 OUT=1]
 * IoAttachDevice [IN=2 OUT=1]
 * IoConnectInterrupt [IN=10 OUT=1]
 * IoCreateDevice [IN=6 OUT=1]
 * IoCreateFile [IN=12 OUT=2]
 * IoGetDeviceInterfaceAlias [IN=2 OUT=1]
 * IoGetDeviceInterfaces [IN=3 OUT=1]
 * IoGetDeviceObjectPointer [IN=2 OUT=2]
 * IoGetDeviceProperty [IN=3 OUT=2]
 * IoOpenDeviceInterfaceRegistryKey [IN=2 OUT=1]
 * IoOpenDeviceRegistryKey [IN=3 OUT=1]
 * IoRegisterDeviceInterface [IN=3 OUT=1]
 * IoRegisterPlugPlayNotification [IN=6 OUT=1]
 * IoReportResourceForDetection [IN=6 OUT=1]
 * IoReportResourceUsage [IN=8 OUT=1]
 * IoVolumeDeviceToDosName [IN=1 OUT=1]
 * IoWMIAllocateInstanceIds [IN=2 OUT=1]
 * IoWMIDeviceObjectToInstanceName [IN=2 OUT=1]
 * IoWMIHandleToInstanceName [IN=2 OUT=1]
 * IoWMIOpenBlock [IN=2 OUT=1]
 * IoWMIQueryAllData [IN=2 OUT=1]
 * IoWMIQueryAllDataMultiple [IN=3 OUT=1]
 * IoWMIQuerySingleInstance [IN=3 OUT=1]
 * IoWMIQuerySingleInstanceMultiple [IN=4 OUT=1]
 * IoWMISuggestInstanceName [IN=3 OUT=1]
 * KeSaveFloatingPointState [IN=0 OUT=1]
 * ObGetObjectSecurity [IN=1 OUT=2]
 * ObReferenceObjectByHandle [IN=4 OUT=2]
 * PoRequestPowerIrp [IN=5 OUT=1]
 * PsCreateSystemThread [IN=5 OUT=2]
 * RtlGUIDFromString [IN=1 OUT=1]
 * RtlHashUnicodeString [IN=3 OUT=1]
 * RtlStringFromGUID [IN=1 OUT=1]
 * RtlUnicodeStringToInteger [IN=2 OUT=1]
 * RtlVolumeDeviceToDosName [IN=1 OUT=1]
 * SeAccessCheck [IN=7 OUT=3]
 * SeAssignSecurity [IN=6 OUT=1]
 * SeAssignSecurityEx [IN=8 OUT=1]
 * WmiQueryTraceInformation [IN=3 OUT=2]
 * ZwCreateDirectoryObject [IN=2 OUT=1]
 * ZwCreateEvent [IN=4 OUT=1]
 * ZwCreateFile [IN=9 OUT=2]
 * ZwCreateKey [IN=5 OUT=2]
 * ZwDeviceIoControlFile [IN=8 OUT=2]
 * ZwEnumerateKey [IN=4 OUT=2]
 * ZwEnumerateValueKey [IN=4 OUT=2]
 * ZwOpenFile [IN=4 OUT=2]
 * ZwOpenKey [IN=2 OUT=1]
 * ZwOpenSection [IN=2 OUT=1]
 * ZwOpenSymbolicLinkObject [IN=2 OUT=1]
 * ZwQueryInformationFile [IN=3 OUT=2]
 * ZwQueryKey [IN=3 OUT=2]
 * ZwQuerySymbolicLinkObject [IN=2 OUT=1]
 * ZwQueryValueKey [IN=4 OUT=2]
 * ZwReadFile [IN=7 OUT=2]
 * ZwSetEvent [IN=1 OUT=1]
 * ZwSetInformationFile [IN=4 OUT=1]
 * ZwWriteFile [IN=8 OUT=1]
 *
 * 441 functions do not return a status code:
 * -------------------------------------------
 * DbgBreakPoint
 * DbgBreakPointWithStatus
 * DbgPrint
 * DbgPrintEx
 * DbgPrintReturnControlC
 * ExAcquireFastMutex
 * ExAcquireFastMutexUnsafe
 * ExAcquireResourceExclusiveLite
 * ExAcquireResourceSharedLite
 * ExAcquireSharedStarveExclusive
 * ExAcquireSharedWaitForExclusive
 * ExAllocateFromPagedLookasideList
 * ExAllocatePool
 * ExAllocatePoolWithQuota
 * ExAllocatePoolWithQuotaTag
 * ExAllocatePoolWithTag
 * ExAllocatePoolWithTagPriority
 * ExConvertExclusiveToSharedLite
 * ExDeleteNPagedLookasideList
 * ExDeletePagedLookasideList
 * ExFreePool
 * ExFreePoolWithTag
 * ExFreeToPagedLookasideList
 * ExGetExclusiveWaiterCount
 * ExGetPreviousMode
 * ExGetSharedWaiterCount
 * ExInitializeNPagedLookasideList
 * ExInitializePagedLookasideList
 * ExInterlockedAddLargeInteger
 * ExInterlockedAddLargeStatistic
 * ExInterlockedAddUlong
 * ExInterlockedCompareExchange64
 * ExInterlockedDecrementLong
 * ExInterlockedExchangeUlong
 * ExInterlockedFlushSList
 * ExInterlockedIncrementLong
 * ExInterlockedInsertHeadList
 * ExInterlockedInsertTailList
 * ExInterlockedPopEntryList
 * ExInterlockedPopEntrySList
 * ExInterlockedPushEntryList
 * ExInterlockedPushEntrySList
 * ExInterlockedRemoveHeadList
 * ExIsProcessorFeaturePresent
 * ExIsResourceAcquiredExclusiveLite
 * ExIsResourceAcquiredSharedLite
 * ExLocalTimeToSystemTime [IN=1 OUT=1]
 * ExNotifyCallback
 * ExQueueWorkItem
 * ExRaiseAccessViolation
 * ExRaiseDatatypeMisalignment
 * ExRaiseStatus
 * ExRegisterCallback
 * ExReinitializeResourceLite
 * ExReleaseFastMutex
 * ExReleaseFastMutexUnsafe
 * ExReleaseResourceForThreadLite
 * ExReleaseResourceLite
 * ExSetResourceOwnerPointer
 * ExSetTimerResolution
 * ExSystemTimeToLocalTime [IN=1 OUT=1]
 * ExTryToAcquireFastMutex
 * ExUnregisterCallback
 * ExVerifySuite
 * ExfInterlockedAddUlong
 * ExfInterlockedInsertHeadList
 * ExfInterlockedInsertTailList
 * ExfInterlockedPopEntryList
 * ExfInterlockedPushEntryList
 * ExfInterlockedRemoveHeadList
 * Exfi386InterlockedDecrementLong
 * Exfi386InterlockedExchangeUlong
 * Exfi386InterlockedIncrementLong
 * Exi386InterlockedDecrementLong
 * Exi386InterlockedExchangeUlong
 * Exi386InterlockedIncrementLong
 * FsRtlIsTotalDeviceFailure
 * HalAllocateCommonBuffer [IN=3 OUT=1]
 * HalExamineMBR [IN=3 OUT=1]
 * HalFreeCommonBuffer
 * HalGetAdapter
 * HalGetBusData
 * HalGetBusDataByOffset
 * HalGetInterruptVector [IN=4 OUT=2]
 * HalReadDmaCounter
 * HalSetBusData
 * HalSetBusDataByOffset
 * HalTranslateBusAddress [IN=4 OUT=1]
 * InterlockedCompareExchange
 * InterlockedDecrement
 * InterlockedExchange
 * InterlockedExchangeAdd
 * InterlockedIncrement
 * InterlockedPopEntrySList
 * InterlockedPushEntrySList
 * IoAcquireCancelSpinLock [IN=0 OUT=1]
 * IoAllocateController
 * IoAllocateErrorLogEntry
 * IoAllocateIrp
 * IoAllocateMdl
 * IoAllocateWorkItem
 * IoAttachDeviceToDeviceStack
 * IoBuildAsynchronousFsdRequest
 * IoBuildDeviceIoControlRequest [IN=7 OUT=2]
 * IoBuildPartialMdl
 * IoBuildSynchronousFsdRequest [IN=6 OUT=1]
 * IoCancelFileOpen
 * IoCancelIrp
 * IoCreateController
 * IoCreateNotificationEvent [IN=1 OUT=1]
 * IoCreateSynchronizationEvent [IN=1 OUT=1]
 * IoCsqInitialize
 * IoCsqInsertIrp
 * IoCsqRemoveIrp
 * IoCsqRemoveNextIrp
 * IoDeleteController
 * IoDeleteDevice
 * IoDetachDevice
 * IoDisconnectInterrupt
 * IoFlushAdapterBuffers
 * IoForwardIrpSynchronously
 * IoFreeAdapterChannel
 * IoFreeController
 * IoFreeErrorLogEntry
 * IoFreeIrp
 * IoFreeMapRegisters
 * IoFreeMdl
 * IoFreeWorkItem
 * IoGetAttachedDevice
 * IoGetAttachedDeviceReference
 * IoGetConfigurationInformation
 * IoGetCurrentProcess
 * IoGetDeviceToVerify
 * IoGetDmaAdapter [IN=2 OUT=1]
 * IoGetDriverObjectExtension
 * IoGetFileObjectGenericMapping
 * IoGetInitialStack
 * IoGetRelatedDeviceObject
 * IoGetStackLimits [IN=0 OUT=2]
 * IoInitializeIrp
 * IoInitializeRemoveLockEx
 * IoInvalidateDeviceRelations
 * IoInvalidateDeviceState
 * IoIsWdmVersionAvailable
 * IoMakeAssociatedIrp
 * IoMapTransfer
 * IoQueueWorkItem
 * IoRaiseHardError
 * IoRaiseInformationalHardError
 * IoRegisterBootDriverReinitialization
 * IoRegisterDriverReinitialization
 * IoReleaseCancelSpinLock
 * IoReleaseRemoveLockAndWaitEx
 * IoReleaseRemoveLockEx
 * IoRemoveShareAccess
 * IoRequestDeviceEject
 * IoReuseIrp
 * IoSetCompletionRoutineEx
 * IoSetHardErrorOrVerifyDevice
 * IoSetShareAccess [IN=3 OUT=1]
 * IoSetStartIoAttributes
 * IoSetThreadHardErrorMode
 * IoStartNextPacket
 * IoStartNextPacketByKey
 * IoStartPacket
 * IoStartTimer
 * IoStopTimer
 * IoUnregisterShutdownNotification
 * IoUpdateShareAccess
 * IoWriteErrorLogEntry
 * IofCompleteRequest
 * KdDisableDebugger
 * KdEnableDebugger
 * KeAcquireInStackQueuedSpinLock
 * KeAcquireInStackQueuedSpinLockAtDpcLevel
 * KeAcquireInterruptSpinLock
 * KeAcquireSpinLock [IN=1 OUT=1]
 * KeAddSystemServiceTable
 * KeAreApcsDisabled
 * KeAttachProcess
 * KeBugCheck
 * KeBugCheckEx
 * KeCancelTimer
 * KeClearEvent
 * KeDeregisterBugCheckCallback
 * KeDetachProcess
 * KeEnterCriticalRegion
 * KeFlushQueuedDpcs
 * KeGetCurrentIrql
 * KeGetCurrentThread
 * KeGetPreviousMode
 * KeGetRecommendedSharedDataAlignment
 * KeInitializeApc
 * KeInitializeDeviceQueue
 * KeInitializeDpc
 * KeInitializeEvent
 * KeInitializeMutex
 * KeInitializeSemaphore
 * KeInitializeSpinLock
 * KeInitializeTimer
 * KeInitializeTimerEx
 * KeInsertByKeyDeviceQueue
 * KeInsertDeviceQueue
 * KeInsertQueueDpc
 * KeLeaveCriticalRegion
 * KeLowerIrql
 * KeQueryInterruptTime
 * KeQueryPerformanceCounter [IN=0 OUT=1]
 * KeQueryPriorityThread
 * KeQuerySystemTime [IN=0 OUT=1]
 * KeQueryTickCount [IN=0 OUT=1]
 * KeQueryTimeIncrement
 * KeRaiseIrql [IN=1 OUT=1]
 * KeRaiseIrqlToDpcLevel
 * KeReadStateEvent
 * KeReadStateMutex
 * KeReadStateSemaphore
 * KeReadStateTimer
 * KeRegisterBugCheckCallback
 * KeReleaseInStackQueuedSpinLock
 * KeReleaseInStackQueuedSpinLockFromDpcLevel
 * KeReleaseInterruptSpinLock
 * KeReleaseMutex
 * KeReleaseSemaphore
 * KeReleaseSpinLock
 * KeRemoveByKeyDeviceQueue
 * KeRemoveDeviceQueue
 * KeRemoveEntryDeviceQueue
 * KeRemoveQueueDpc
 * KeResetEvent
 * KeSetBasePriorityThread
 * KeSetEvent
 * KeSetImportanceDpc
 * KeSetPriorityThread
 * KeSetTargetProcessorDpc
 * KeSetTimeUpdateNotifyRoutine
 * KeSetTimer
 * KeSetTimerEx
 * KeStallExecutionProcessor
 * KeSynchronizeExecution
 * KefAcquireSpinLockAtDpcLevel
 * KefReleaseSpinLockFromDpcLevel
 * MmAllocateContiguousMemory
 * MmAllocateContiguousMemorySpecifyCache
 * MmAllocateMappingAddress
 * MmAllocateNonCachedMemory
 * MmAllocatePagesForMdl
 * MmBuildMdlForNonPagedPool
 * MmCreateMdl
 * MmFlushImageSection
 * MmFreeContiguousMemory
 * MmFreeContiguousMemorySpecifyCache
 * MmFreeMappingAddress
 * MmFreeNonCachedMemory
 * MmFreePagesFromMdl
 * MmGetPhysicalAddress
 * MmGetPhysicalMemoryRanges
 * MmGetSystemRoutineAddress
 * MmGetVirtualForPhysical
 * MmIsAddressValid
 * MmIsDriverVerifying
 * MmIsNonPagedSystemAddressValid
 * MmIsThisAnNtAsSystem
 * MmLockPagableDataSection
 * MmLockPagableImageSection
 * MmLockPagableSectionByHandle
 * MmMapIoSpace
 * MmMapLockedPages
 * MmMapLockedPagesSpecifyCache
 * MmMapLockedPagesWithReservedMapping
 * MmMapVideoDisplay
 * MmPageEntireDriver
 * MmProbeAndLockPages
 * MmProbeAndLockProcessPages
 * MmQuerySystemSize
 * MmResetDriverPaging
 * MmSecureVirtualMemory
 * MmSizeOfMdl
 * MmUnlockPagableImageSection
 * MmUnlockPages
 * MmUnmapIoSpace
 * MmUnmapLockedPages
 * MmUnmapReservedMapping
 * MmUnmapVideoDisplay
 * MmUnsecureVirtualMemory
 * ObDereferenceSecurityDescriptor
 * ObMakeTemporaryObject
 * ObReferenceSecurityDescriptor
 * ObReleaseObjectSecurity
 * ObfDereferenceObject
 * ObfReferenceObject
 * PoRegisterDeviceForIdleDetection
 * PoRegisterSystemState
 * PoSetPowerState
 * PoSetSystemState
 * PoStartNextPowerIrp
 * PoUnregisterSystemState
 * ProbeForRead
 * ProbeForWrite
 * PsGetCurrentProcessId
 * PsGetCurrentThreadId
 * PsGetVersion
 * READ_PORT_BUFFER_UCHAR
 * READ_PORT_BUFFER_ULONG
 * READ_PORT_BUFFER_USHORT
 * READ_PORT_UCHAR
 * READ_PORT_ULONG
 * READ_PORT_USHORT
 * READ_REGISTER_BUFFER_UCHAR
 * READ_REGISTER_BUFFER_ULONG
 * READ_REGISTER_BUFFER_USHORT
 * READ_REGISTER_UCHAR
 * READ_REGISTER_ULONG
 * READ_REGISTER_USHORT
 * RtlAnsiStringToUnicodeSize
 * RtlAreBitsClear
 * RtlAreBitsSet
 * RtlAssert
 * RtlClearAllBits
 * RtlClearBit
 * RtlClearBits
 * RtlCompareMemory
 * RtlCompareString
 * RtlCompareUnicodeString
 * RtlConvertLongToLargeInteger
 * RtlConvertUlongToLargeInteger
 * RtlCopyString
 * RtlCopyUnicodeString
 * RtlEnlargedIntegerMultiply
 * RtlEnlargedUnsignedDivide
 * RtlEnlargedUnsignedMultiply
 * RtlEqualString
 * RtlEqualUnicodeString
 * RtlExtendedIntegerMultiply
 * RtlExtendedLargeIntegerDivide [IN=2 OUT=1]
 * RtlExtendedMagicDivide
 * RtlFindClearBits
 * RtlFindClearBitsAndSet
 * RtlFindClearRuns [IN=3 OUT=1]
 * RtlFindFirstRunClear [IN=1 OUT=1]
 * RtlFindLastBackwardRunClear [IN=2 OUT=1]
 * RtlFindLeastSignificantBit
 * RtlFindLongestRunClear [IN=1 OUT=1]
 * RtlFindMostSignificantBit
 * RtlFindNextForwardRunClear [IN=2 OUT=1]
 * RtlFindSetBits
 * RtlFindSetBitsAndClear
 * RtlFreeAnsiString
 * RtlFreeRangeList
 * RtlFreeUnicodeString
 * RtlGetCallersAddress
 * RtlInitAnsiString
 * RtlInitString
 * RtlInitUnicodeString
 * RtlInitializeBitMap
 * RtlInitializeRangeList
 * RtlLargeIntegerAdd
 * RtlLargeIntegerArithmeticShift
 * RtlLargeIntegerDivide
 * RtlLargeIntegerNegate
 * RtlLargeIntegerShiftLeft
 * RtlLargeIntegerShiftRight
 * RtlLargeIntegerSubtract
 * RtlLengthSecurityDescriptor
 * RtlMapGenericMask
 * RtlNumberOfClearBits
 * RtlNumberOfSetBits
 * RtlPrefetchMemoryNonTemporal
 * RtlPrefixUnicodeString
 * RtlSetAllBits
 * RtlSetBit
 * RtlSetBits
 * RtlTestBit
 * RtlTimeFieldsToTime
 * RtlTimeToTimeFields
 * RtlUlongByteSwap
 * RtlUlonglongByteSwap
 * RtlUnicodeStringToAnsiSize
 * RtlUpcaseUnicodeChar
 * RtlUpperChar
 * RtlUpperString
 * RtlUshortByteSwap
 * RtlValidRelativeSecurityDescriptor
 * RtlValidSecurityDescriptor
 * RtlWalkFrameChain
 * RtlxUnicodeStringToAnsiSize
 * SeSinglePrivilegeCheck
 * SeValidSecurityDescriptor
 * VerSetConditionMask
 * WRITE_PORT_BUFFER_UCHAR
 * WRITE_PORT_BUFFER_ULONG
 * WRITE_PORT_BUFFER_USHORT
 * WRITE_PORT_UCHAR
 * WRITE_PORT_ULONG
 * WRITE_PORT_USHORT
 * WRITE_REGISTER_BUFFER_UCHAR
 * WRITE_REGISTER_BUFFER_ULONG
 * WRITE_REGISTER_BUFFER_USHORT
 * WRITE_REGISTER_UCHAR
 * WRITE_REGISTER_ULONG
 * WRITE_REGISTER_USHORT
 * _stricmp
 * _strlwr
 * _strnicmp
 * _strnset
 * _strrev
 * _strset
 * _strupr
 * _wcsicmp
 * _wcslwr
 * _wcsnicmp
 * _wcsnset
 * _wcsrev
 * _wcsupr
 * memchr
 * memcpy
 * memmove
 * memset
 * strcat
 * strchr
 * strcmp
 * strcpy
 * strlen
 * strncat
 * strncmp
 * strncpy
 * strrchr
 * strspn
 * strstr
 * wcscat
 * wcschr
 * wcscmp
 * wcscpy
 * wcscspn
 * wcslen
 * wcsncat
 * wcsncmp
 * wcsncpy
 * wcsrchr
 * wcsspn
 * wcsstr
 *
 * 73 functions return a status code but have no codes defined:
 * ------------------------------------------------------------------
 * DbgQueryDebugFilterState
 * DbgSetDebugFilterState
 * ExExtendZone
 * ExInitializeZone
 * ExInterlockedExtendZone
 * HalAssignSlotResources
 * IoAcquireRemoveLockEx
 * IoAllocateAdapterChannel
 * IoAssignResources
 * IoAttachDeviceByPointer
 * IoCreateDisk
 * IoCreateUnprotectedSymbolicLink
 * IoQueryDeviceDescription
 * IoReadDiskSignature
 * IoReadPartitionTable
 * IoReadPartitionTableEx
 * IoReportResourceUsage [IN=8 OUT=1]
 * IoSetPartitionInformation
 * IoSetPartitionInformationEx
 * IoWritePartitionTable
 * IoWritePartitionTableEx
 * IofCallDriver
 * KePulseEvent
 * MmCreateSection
 * MmIsVerifierEnabled
 * MmMapUserAddressesToPage
 * MmMapViewInSessionSpace
 * MmMapViewInSystemSpace
 * MmMarkPhysicalMemoryAsBad
 * MmMarkPhysicalMemoryAsGood
 * MmRemovePhysicalMemory
 * MmUnmapViewInSessionSpace
 * MmUnmapViewInSystemSpace
 * NtClose
 * NtCreateEvent
 * NtCreateFile
 * NtDeviceIoControlFile
 * NtMapViewOfSection
 * NtOpenFile
 * NtOpenProcess
 * NtQueryInformationFile
 * NtQueryInformationProcess
 * NtReadFile
 * NtSetEvent
 * NtSetInformationFile
 * NtSetInformationThread
 * NtWaitForSingleObject
 * NtWriteFile
 * ObAssignSecurity
 * ObInsertObject
 * ObLogSecurityDescriptor
 * ObOpenObjectByName
 * ObOpenObjectByPointer
 * ObQueryObjectAuditingByHandle
 * ObReferenceObjectByName
 * PoRequestShutdownEvent
 * PsCreateSystemProcess
 * PsTerminateSystemThread
 * RtlAddRange
 * RtlCopyRangeList
 * RtlDeleteOwnersRanges
 * RtlDeleteRange
 * RtlFindRange
 * RtlGetFirstRange
 * RtlGetNextRange
 * RtlInvertRangeList
 * RtlIsRangeAvailable
 * RtlMergeRangeLists
 * SeAccessCheck [IN=7 OUT=3]
 * ZwCancelTimer
 * ZwCreateTimer
 * ZwOpenTimer
 * ZwSetTimer
 *
 * 44 functions only have success codes:
 * ---------------------------------------
 * CmRegisterCallback ['STATUS_SUCCESS'] [IN=2 OUT=1]
 * ExCreateCallback ['STATUS_SUCCESS'] [IN=3 OUT=1]
 * ExDeleteResourceLite ['STATUS_SUCCESS']
 * ExInitializeResourceLite ['STATUS_SUCCESS']
 * IoCreateFile ['STATUS_SUCCESS'] [IN=12 OUT=2]
 * IoCreateSymbolicLink ['STATUS_SUCCESS']
 * IoDeleteSymbolicLink ['STATUS_SUCCESS']
 * IoInitializeTimer ['STATUS_SUCCESS']
 * IoRegisterPlugPlayNotification ['STATUS_SUCCESS'] [IN=6 OUT=1]
 * IoRegisterShutdownNotification ['STATUS_SUCCESS']
 * IoReportDetectedDevice ['STATUS_SUCCESS']
 * IoSetSystemPartition ['STATUS_SUCCESS']
 * IoUnregisterPlugPlayNotification ['STATUS_SUCCESS']
 * IoVolumeDeviceToDosName ['STATUS_SUCCESS'] [IN=1 OUT=1]
 * IoWMIOpenBlock ['STATUS_SUCCESS'] [IN=2 OUT=1]
 * IoWMISetNotificationCallback ['STATUS_SUCCESS']
 * KeDelayExecutionThread ['STATUS_SUCCESS', 'STATUS_ALERTED', 'STATUS_USER_APC']
 * KeRestoreFloatingPointState ['STATUS_SUCCESS']
 * KeWaitForMultipleObjects ['STATUS_SUCCESS', 'STATUS_ALERTED', 'STATUS_USER_APC', 'STATUS_ABANDONED_WAIT_63', 'STATUS_WAIT_0', 'STATUS_WAIT_63', 'STATUS_ABANDONED_WAIT_0', 'STATUS_TIMEOUT']
 * KeWaitForMutexObject ['STATUS_SUCCESS', 'STATUS_ALERTED', 'STATUS_ABANDONED_WAIT_0', 'STATUS_USER_APC', 'STATUS_TIMEOUT']
 * KeWaitForSingleObject ['STATUS_SUCCESS', 'STATUS_ALERTED', 'STATUS_ABANDONED_WAIT_0', 'STATUS_USER_APC', 'STATUS_TIMEOUT']
 * PoCallDriver ['STATUS_SUCCESS', 'STATUS_PENDING']
 * PsCreateSystemThread ['STATUS_SUCCESS'] [IN=5 OUT=2]
 * RtlAnsiStringToUnicodeString ['STATUS_SUCCESS']
 * RtlCheckRegistryKey ['STATUS_SUCCESS']
 * RtlCreateRegistryKey ['STATUS_SUCCESS']
 * RtlDeleteRegistryValue ['STATUS_SUCCESS']
 * RtlGUIDFromString ['STATUS_SUCCESS'] [IN=1 OUT=1]
 * RtlGetVersion ['STATUS_SUCCESS']
 * RtlStringFromGUID ['STATUS_SUCCESS'] [IN=1 OUT=1]
 * RtlUnicodeStringToAnsiString ['STATUS_SUCCESS']
 * RtlUpcaseUnicodeString ['STATUS_SUCCESS']
 * RtlVolumeDeviceToDosName ['STATUS_SUCCESS'] [IN=1 OUT=1]
 * RtlWriteRegistryValue ['STATUS_SUCCESS']
 * SeDeassignSecurity ['STATUS_SUCCESS']
 * ZwCreateKey ['STATUS_SUCCESS'] [IN=5 OUT=2]
 * ZwFlushKey ['STATUS_SUCCESS']
 * ZwMakeTemporaryObject ['STATUS_SUCCESS']
 * ZwOpenFile ['STATUS_SUCCESS'] [IN=4 OUT=2]
 * ZwOpenSymbolicLinkObject ['STATUS_SUCCESS'] [IN=2 OUT=1]
 * ZwQueryInformationFile ['STATUS_SUCCESS'] [IN=3 OUT=2]
 * ZwReadFile ['STATUS_SUCCESS'] [IN=7 OUT=2]
 * ZwSetInformationFile ['STATUS_SUCCESS'] [IN=4 OUT=1]
 * ZwWriteFile ['STATUS_SUCCESS'] [IN=8 OUT=1]
**/

