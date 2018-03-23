#define NDIS_MINIPORT_DRIVER

#define NDIS51_MINIPORT

#include <ndis.h>
#include <ntdef.h>

#include "s2e.h"
#include "symbhw.h"
#include "hook.h"
#include <ResourceTracker.h>

#include "winxp-ndis-miniport-custom.h"
//NdisCopyBuffer
VOID
S2EHook_NdisCopyBuffer(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_BUFFER*    Buffer,
    /* IN */ NDIS_HANDLE    PoolHandle,
    /* IN */ PVOID    MemoryDescriptor,
    /* IN */ UINT    Offset,
    /* IN */ UINT    Length
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisCopyBuffer, "NdisCopyBuffer", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisCopyBuffer(    Status,    Buffer,    PoolHandle,    MemoryDescriptor,    Offset,    Length);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisCopyBuffer", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisCopyBuffer(    Status,    Buffer,    PoolHandle,    MemoryDescriptor,    Offset,    Length);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisCopyBuffer", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMCmRegisterAddressFamily
NDIS_STATUS
S2EHook_NdisMCmRegisterAddressFamily(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ PCO_ADDRESS_FAMILY    AddressFamily,
    /* IN */ PNDIS_CALL_MANAGER_CHARACTERISTICS    CmCharacteristics,
    /* IN */ UINT    SizeOfCmCharacteristics
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMCmRegisterAddressFamily, "NdisMCmRegisterAddressFamily", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMCmRegisterAddressFamily(    MiniportAdapterHandle,    AddressFamily,    CmCharacteristics,    SizeOfCmCharacteristics);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMCmRegisterAddressFamily", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMCmRegisterAddressFamily(    MiniportAdapterHandle,    AddressFamily,    CmCharacteristics,    SizeOfCmCharacteristics);
        S2EMessageFmt("%s returned %#x\n", "NdisMCmRegisterAddressFamily", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMCmRegisterAddressFamily", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMCmCreateVc
NDIS_STATUS
S2EHook_NdisMCmCreateVc(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ NDIS_HANDLE    NdisAfHandle,
    /* IN */ NDIS_HANDLE    MiniportVcContext,
    /* OUT */ PNDIS_HANDLE    NdisVcHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMCmCreateVc, "NdisMCmCreateVc", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMCmCreateVc(    MiniportAdapterHandle,    NdisAfHandle,    MiniportVcContext,    NdisVcHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMCmCreateVc", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMCmCreateVc(    MiniportAdapterHandle,    NdisAfHandle,    MiniportVcContext,    NdisVcHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisMCmCreateVc", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMCmCreateVc", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisWriteEventLogEntry
NDIS_STATUS
S2EHook_NdisWriteEventLogEntry(
    /* IN */ PVOID    LogHandle,
    /* IN */ NDIS_STATUS    EventCode,
    /* IN */ ULONG    UniqueEventValue,
    /* IN */ USHORT    NumStrings,
    /* IN */ PVOID    StringsList,
    /* IN */ ULONG    DataSize,
    /* IN */ PVOID    Data
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisWriteEventLogEntry, "NdisWriteEventLogEntry", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisWriteEventLogEntry(    LogHandle,    EventCode,    UniqueEventValue,    NumStrings,    StringsList,    DataSize,    Data);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisWriteEventLogEntry", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisWriteEventLogEntry(    LogHandle,    EventCode,    UniqueEventValue,    NumStrings,    StringsList,    DataSize,    Data);
        S2EMessageFmt("%s returned %#x\n", "NdisWriteEventLogEntry", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_BUFFER_TOO_SHORT, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisWriteEventLogEntry", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_BUFFER_TOO_SHORT,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisWriteConfiguration
VOID
S2EHook_NdisWriteConfiguration(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    WrapperConfigurationContext,
    /* IN */ PNDIS_STRING    Keyword,
    /* IN */ PNDIS_CONFIGURATION_PARAMETER    ParameterValue
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisWriteConfiguration, "NdisWriteConfiguration", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisWriteConfiguration(    Status,    WrapperConfigurationContext,    Keyword,    ParameterValue);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisWriteConfiguration", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisWriteConfiguration(    Status,    WrapperConfigurationContext,    Keyword,    ParameterValue);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisWriteConfiguration", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE,    NDIS_STATUS_NOT_SUPPORTED);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisCoDeleteVc
NDIS_STATUS
S2EHook_NdisCoDeleteVc(
    /* IN */ NDIS_HANDLE    NdisVcHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisCoDeleteVc, "NdisCoDeleteVc", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisCoDeleteVc(    NdisVcHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisCoDeleteVc", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisCoDeleteVc(    NdisVcHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisCoDeleteVc", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_CLOSING, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisCoDeleteVc", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_CLOSING);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMRegisterIoPortRange
NDIS_STATUS
S2EHook_NdisMRegisterIoPortRange(
    /* OUT */ PVOID*    PortOffset,
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ UINT    InitialPort,
    /* IN */ UINT    NumberOfPorts
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMRegisterIoPortRange, "NdisMRegisterIoPortRange", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMRegisterIoPortRange(    PortOffset,    MiniportAdapterHandle,    InitialPort,    NumberOfPorts);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMRegisterIoPortRange", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMRegisterIoPortRange(    PortOffset,    MiniportAdapterHandle,    InitialPort,    NumberOfPorts);
        S2EMessageFmt("%s returned %#x\n", "NdisMRegisterIoPortRange", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMRegisterIoPortRange", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_RESOURCE_CONFLICT,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisFreeMemory
VOID
S2EHook_NdisFreeMemory(
    /* IN */ PVOID    VirtualAddress,
    /* IN */ UINT    Length,
    /* IN */ UINT    MemoryFlags
)
{



    NdisFreeMemory(    VirtualAddress,    Length,    MemoryFlags);
    {
        UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();
        S2EAllocateResource("NdisFreeMemory", "ndis.sys", CallSite, (UINT_PTR)VirtualAddress, FALSE);
    }

    return;


}

//NdisOpenConfigurationKeyByName
VOID
S2EHook_NdisOpenConfigurationKeyByName(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    ConfigurationHandle,
    /* IN */ PNDIS_STRING    SubKeyName,
    /* OUT */ PNDIS_HANDLE    SubKeyHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisOpenConfigurationKeyByName, "NdisOpenConfigurationKeyByName", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisOpenConfigurationKeyByName(    Status,    ConfigurationHandle,    SubKeyName,    SubKeyHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisOpenConfigurationKeyByName", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisOpenConfigurationKeyByName(    Status,    ConfigurationHandle,    SubKeyName,    SubKeyHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisOpenConfigurationKeyByName", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMMapIoSpace
NDIS_STATUS
S2EHook_NdisMMapIoSpace(
    /* OUT */ PVOID*    VirtualAddress,
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ NDIS_PHYSICAL_ADDRESS    PhysicalAddress,
    /* IN */ UINT    Length
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMMapIoSpace, "NdisMMapIoSpace", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        S2EMessageFmt("%s PhysAddr=%#x %#x Length=%#x\n", __FUNCTION__, PhysicalAddress.HighPart,
                      PhysicalAddress.LowPart, Length);

        RetVal = NdisMMapIoSpace(    VirtualAddress,    MiniportAdapterHandle,    PhysicalAddress,    Length);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMMapIoSpace", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        S2EMessageFmt("%s PhysAddr=%#x %#x Length=%#x\n", __FUNCTION__, PhysicalAddress.HighPart,
                      PhysicalAddress.LowPart, Length);

        RetVal = NdisMMapIoSpace(    VirtualAddress,    MiniportAdapterHandle,    PhysicalAddress,    Length);
        S2EMessageFmt("%s returned %#x\n", "NdisMMapIoSpace", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMMapIoSpace", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_RESOURCE_CONFLICT,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisIMRegisterLayeredMiniport
NDIS_STATUS
S2EHook_NdisIMRegisterLayeredMiniport(
    /* IN */ NDIS_HANDLE    NdisWrapperHandle,
    /* IN */ PNDIS_MINIPORT_CHARACTERISTICS    MiniportCharacteristics,
    /* IN */ UINT    CharacteristicsLength,
    /* OUT */ PNDIS_HANDLE    DriverHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisIMRegisterLayeredMiniport, "NdisIMRegisterLayeredMiniport", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisIMRegisterLayeredMiniport(    NdisWrapperHandle,    MiniportCharacteristics,    CharacteristicsLength,    DriverHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisIMRegisterLayeredMiniport", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisIMRegisterLayeredMiniport(    NdisWrapperHandle,    MiniportCharacteristics,    CharacteristicsLength,    DriverHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisIMRegisterLayeredMiniport", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisIMRegisterLayeredMiniport", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_BAD_CHARACTERISTICS,    NDIS_STATUS_BAD_VERSION,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMCreateLog
NDIS_STATUS
S2EHook_NdisMCreateLog(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ UINT    Size,
    /* OUT */ PNDIS_HANDLE    LogHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMCreateLog, "NdisMCreateLog", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMCreateLog(    MiniportAdapterHandle,    Size,    LogHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMCreateLog", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMCreateLog(    MiniportAdapterHandle,    Size,    LogHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisMCreateLog", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMCreateLog", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMPromoteMiniport
NDIS_STATUS
S2EHook_NdisMPromoteMiniport(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMPromoteMiniport, "NdisMPromoteMiniport", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMPromoteMiniport(    MiniportAdapterHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMPromoteMiniport", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMPromoteMiniport(    MiniportAdapterHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisMPromoteMiniport", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMPromoteMiniport", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisIMDeInitializeDeviceInstance
NDIS_STATUS
S2EHook_NdisIMDeInitializeDeviceInstance(
    /* IN */ NDIS_HANDLE    NdisMiniportHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisIMDeInitializeDeviceInstance, "NdisIMDeInitializeDeviceInstance", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisIMDeInitializeDeviceInstance(    NdisMiniportHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisIMDeInitializeDeviceInstance", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisIMDeInitializeDeviceInstance(    NdisMiniportHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisIMDeInitializeDeviceInstance", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisIMDeInitializeDeviceInstance", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMRemoveMiniport
NDIS_STATUS
S2EHook_NdisMRemoveMiniport(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMRemoveMiniport, "NdisMRemoveMiniport", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMRemoveMiniport(    MiniportAdapterHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMRemoveMiniport", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMRemoveMiniport(    MiniportAdapterHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisMRemoveMiniport", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMRemoveMiniport", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisAllocatePacketPool
VOID
S2EHook_NdisAllocatePacketPool(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_HANDLE    PoolHandle,
    /* IN */ UINT    NumberOfDescriptors,
    /* IN */ UINT    ProtocolReservedLength
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisAllocatePacketPool, "NdisAllocatePacketPool", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisAllocatePacketPool(    Status,    PoolHandle,    NumberOfDescriptors,    ProtocolReservedLength);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisAllocatePacketPool", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisAllocatePacketPool(    Status,    PoolHandle,    NumberOfDescriptors,    ProtocolReservedLength);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisAllocatePacketPool", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMFreeSharedMemory
VOID
S2EHook_NdisMFreeSharedMemory(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ ULONG    Length,
    /* IN */ BOOLEAN    Cached,
    /* IN */ PVOID    VirtualAddress,
    /* IN */ NDIS_PHYSICAL_ADDRESS    PhysicalAddress
)
{



    {
        //Put this before to avoid forking in the kernel
        if (VirtualAddress) {
            S2EFreeDmaRegion(PhysicalAddress.QuadPart, Length);
        }
    }

    NdisMFreeSharedMemory(    MiniportAdapterHandle,    Length,    Cached,    VirtualAddress,    PhysicalAddress);
    return;


}

//NdisOpenConfiguration
VOID
S2EHook_NdisOpenConfiguration(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_HANDLE    ConfigurationHandle,
    /* IN */ NDIS_HANDLE    WrapperConfigurationContext
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisOpenConfiguration, "NdisOpenConfiguration", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisOpenConfiguration(    Status,    ConfigurationHandle,    WrapperConfigurationContext);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisOpenConfiguration", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisOpenConfiguration(    Status,    ConfigurationHandle,    WrapperConfigurationContext);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisOpenConfiguration", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMInitializeScatterGatherDma
NDIS_STATUS
S2EHook_NdisMInitializeScatterGatherDma(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ BOOLEAN    Dma64BitAddresses,
    /* IN */ ULONG    MaximumPhysicalMapping
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMInitializeScatterGatherDma, "NdisMInitializeScatterGatherDma", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMInitializeScatterGatherDma(    MiniportAdapterHandle,    Dma64BitAddresses,    MaximumPhysicalMapping);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMInitializeScatterGatherDma", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMInitializeScatterGatherDma(    MiniportAdapterHandle,    Dma64BitAddresses,    MaximumPhysicalMapping);
        S2EMessageFmt("%s returned %#x\n", "NdisMInitializeScatterGatherDma", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMInitializeScatterGatherDma", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_NOT_SUPPORTED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMAllocateSharedMemoryAsync
NDIS_STATUS
S2EHook_NdisMAllocateSharedMemoryAsync(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ ULONG    Length,
    /* IN */ BOOLEAN    Cached,
    /* IN */ PVOID    Context
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMAllocateSharedMemoryAsync, "NdisMAllocateSharedMemoryAsync", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMAllocateSharedMemoryAsync(    MiniportAdapterHandle,    Length,    Cached,    Context);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMAllocateSharedMemoryAsync", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMAllocateSharedMemoryAsync(    MiniportAdapterHandle,    Length,    Cached,    Context);
        S2EMessageFmt("%s returned %#x\n", "NdisMAllocateSharedMemoryAsync", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMAllocateSharedMemoryAsync", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisCoCreateVc
NDIS_STATUS
S2EHook_NdisCoCreateVc(
    /* IN */ NDIS_HANDLE    NdisBindingHandle,
    /* IN */ NDIS_HANDLE    NdisAfHandle,
    /* IN */ NDIS_HANDLE    ProtocolVcContext,
    /* IN */ PNDIS_HANDLE    NdisVcHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisCoCreateVc, "NdisCoCreateVc", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisCoCreateVc(    NdisBindingHandle,    NdisAfHandle,    ProtocolVcContext,    NdisVcHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisCoCreateVc", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisCoCreateVc(    NdisBindingHandle,    NdisAfHandle,    ProtocolVcContext,    NdisVcHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisCoCreateVc", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisCoCreateVc", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisAllocateMemoryWithTag
NDIS_STATUS
S2EHook_NdisAllocateMemoryWithTag(
    /* OUT */ PVOID*    VirtualAddress,
    /* IN */ UINT    Length,
    /* IN */ ULONG    Tag
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisAllocateMemoryWithTag, "NdisAllocateMemoryWithTag", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisAllocateMemoryWithTag(    VirtualAddress,    Length,    Tag);
        if (NT_SUCCESS(RetVal)) {
            S2EAllocateResource("NdisAllocateMemoryWithTag", "ndis.sys", CallSite, (UINT_PTR)*VirtualAddress, TRUE);
        }

        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisAllocateMemoryWithTag", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisAllocateMemoryWithTag(    VirtualAddress,    Length,    Tag);
        if (NT_SUCCESS(RetVal)) {
            S2EAllocateResource("NdisAllocateMemoryWithTag", "ndis.sys", CallSite, (UINT_PTR)*VirtualAddress, TRUE);
        }

        S2EMessageFmt("%s returned %#x\n", "NdisAllocateMemoryWithTag", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisAllocateMemoryWithTag", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();
        *VirtualAddress = NULL;
        return ConcolicStatus;
    }
}

//NdisMRegisterMiniport
NDIS_STATUS
S2EHook_NdisMRegisterMiniport(
    /* IN */ NDIS_HANDLE    NdisWrapperHandle,
    /* IN */ PNDIS_MINIPORT_CHARACTERISTICS    MiniportCharacteristics,
    /* IN */ UINT    CharacteristicsLength
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMRegisterMiniport, "NdisMRegisterMiniport", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMRegisterMiniport(    NdisWrapperHandle,    MiniportCharacteristics,    CharacteristicsLength);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisMRegisterMiniport_RegisterEntryPoints(NdisWrapperHandle, MiniportCharacteristics, CharacteristicsLength);
        }

        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMRegisterMiniport", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMRegisterMiniport(    NdisWrapperHandle,    MiniportCharacteristics,    CharacteristicsLength);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisMRegisterMiniport_RegisterEntryPoints(NdisWrapperHandle, MiniportCharacteristics, CharacteristicsLength);
        }

        S2EMessageFmt("%s returned %#x\n", "NdisMRegisterMiniport", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMRegisterMiniport", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_BAD_CHARACTERISTICS,    NDIS_STATUS_BAD_VERSION,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisReadNetworkAddress
VOID
S2EHook_NdisReadNetworkAddress(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PVOID*    NetworkAddress,
    /* OUT */ PUINT    NetworkAddressLength,
    /* IN */ NDIS_HANDLE    ConfigurationHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisReadNetworkAddress, "NdisReadNetworkAddress", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisReadNetworkAddress(    Status,    NetworkAddress,    NetworkAddressLength,    ConfigurationHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisReadNetworkAddress", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisReadNetworkAddress(    Status,    NetworkAddress,    NetworkAddressLength,    ConfigurationHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisReadNetworkAddress", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisAllocatePacket
VOID
S2EHook_NdisAllocatePacket(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_PACKET*    Packet,
    /* IN */ NDIS_HANDLE    PoolHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisAllocatePacket, "NdisAllocatePacket", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisAllocatePacket(    Status,    Packet,    PoolHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisAllocatePacket", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisAllocatePacket(    Status,    Packet,    PoolHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisAllocatePacket", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisClDeregisterSap
NDIS_STATUS
S2EHook_NdisClDeregisterSap(
    /* IN */ NDIS_HANDLE    NdisSapHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisClDeregisterSap, "NdisClDeregisterSap", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisClDeregisterSap(    NdisSapHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisClDeregisterSap", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisClDeregisterSap(    NdisSapHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisClDeregisterSap", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisClDeregisterSap", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisInitializeWrapper
VOID
S2EHook_NdisInitializeWrapper(
    /*  */ PNDIS_HANDLE    NdisWrapperHandle,
    /*  */ PVOID    SystemSpecific1,
    /*  */ PVOID    SystemSpecific2,
    /*  */ PVOID    SystemSpecific3
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisInitializeWrapper, "NdisInitializeWrapper", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisInitializeWrapper(    NdisWrapperHandle,    SystemSpecific1,    SystemSpecific2,    SystemSpecific3);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisInitializeWrapper", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisInitializeWrapper(    NdisWrapperHandle,    SystemSpecific1,    SystemSpecific2,    SystemSpecific3);
        return;
    } else {
        S2EIncrementFaultCount();
        *NdisWrapperHandle = NULL;
    }
}

//NdisDprAllocatePacketNonInterlocked
VOID
S2EHook_NdisDprAllocatePacketNonInterlocked(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_PACKET*    Packet,
    /* IN */ NDIS_HANDLE    PoolHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisDprAllocatePacketNonInterlocked, "NdisDprAllocatePacketNonInterlocked", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisDprAllocatePacketNonInterlocked(    Status,    Packet,    PoolHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisDprAllocatePacketNonInterlocked", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisDprAllocatePacketNonInterlocked(    Status,    Packet,    PoolHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisDprAllocatePacketNonInterlocked", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisDprAllocatePacket
VOID
S2EHook_NdisDprAllocatePacket(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_PACKET*    Packet,
    /* IN */ NDIS_HANDLE    PoolHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisDprAllocatePacket, "NdisDprAllocatePacket", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisDprAllocatePacket(    Status,    Packet,    PoolHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisDprAllocatePacket", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisDprAllocatePacket(    Status,    Packet,    PoolHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisDprAllocatePacket", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisAllocateMemory
NDIS_STATUS
S2EHook_NdisAllocateMemory(
    /* OUT */ PVOID*    VirtualAddress,
    /* IN */ UINT    Length,
    /* IN */ UINT    MemoryFlags,
    /* IN */ NDIS_PHYSICAL_ADDRESS    HighestAcceptableAddress
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisAllocateMemory, "NdisAllocateMemory", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisAllocateMemory(    VirtualAddress,    Length,    MemoryFlags,    HighestAcceptableAddress);
        if (NT_SUCCESS(RetVal)) {
            S2EAllocateResource("NdisAllocateMemory", "ndis.sys", CallSite, (UINT_PTR)*VirtualAddress, TRUE);
        }

        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisAllocateMemory", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisAllocateMemory(    VirtualAddress,    Length,    MemoryFlags,    HighestAcceptableAddress);
        if (NT_SUCCESS(RetVal)) {
            S2EAllocateResource("NdisAllocateMemory", "ndis.sys", CallSite, (UINT_PTR)*VirtualAddress, TRUE);
        }

        S2EMessageFmt("%s returned %#x\n", "NdisAllocateMemory", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisAllocateMemory", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();
        *VirtualAddress = NULL;
        return ConcolicStatus;
    }
}

//NdisReadConfiguration
VOID
S2EHook_NdisReadConfiguration(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_CONFIGURATION_PARAMETER*    ParameterValue,
    /* IN */ NDIS_HANDLE    ConfigurationHandle,
    /* IN */ PNDIS_STRING    Keyword,
    /* IN */ NDIS_PARAMETER_TYPE    ParameterType
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisReadConfiguration, "NdisReadConfiguration", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisReadConfiguration(    Status,    ParameterValue,    ConfigurationHandle,    Keyword,    ParameterType);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisReadConfiguration", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisReadConfiguration(    Status,    ParameterValue,    ConfigurationHandle,    Keyword,    ParameterType);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisReadConfiguration", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMWriteLogData
NDIS_STATUS
S2EHook_NdisMWriteLogData(
    /* IN */ NDIS_HANDLE    LogHandle,
    /* IN */ PVOID    LogBuffer,
    /* IN */ UINT    LogBufferSize
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMWriteLogData, "NdisMWriteLogData", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMWriteLogData(    LogHandle,    LogBuffer,    LogBufferSize);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMWriteLogData", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMWriteLogData(    LogHandle,    LogBuffer,    LogBufferSize);
        S2EMessageFmt("%s returned %#x\n", "NdisMWriteLogData", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_BUFFER_OVERFLOW, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMWriteLogData", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_BUFFER_OVERFLOW);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMAllocateMapRegisters
NDIS_STATUS
S2EHook_NdisMAllocateMapRegisters(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ UINT    DmaChannel,
    /* IN */ BOOLEAN    Dma32BitAddresses,
    /* IN */ ULONG    PhysicalMapRegistersNeeded,
    /* IN */ ULONG    MaximumPhysicalMapping
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMAllocateMapRegisters, "NdisMAllocateMapRegisters", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMAllocateMapRegisters(    MiniportAdapterHandle,    DmaChannel,    Dma32BitAddresses,    PhysicalMapRegistersNeeded,    MaximumPhysicalMapping);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMAllocateMapRegisters", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMAllocateMapRegisters(    MiniportAdapterHandle,    DmaChannel,    Dma32BitAddresses,    PhysicalMapRegistersNeeded,    MaximumPhysicalMapping);
        S2EMessageFmt("%s returned %#x\n", "NdisMAllocateMapRegisters", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMAllocateMapRegisters", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisAllocateBuffer
VOID
S2EHook_NdisAllocateBuffer(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_BUFFER*    Buffer,
    /* IN */ NDIS_HANDLE    PoolHandle,
    /* IN */ PVOID    VirtualAddress,
    /* IN */ UINT    Length
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisAllocateBuffer, "NdisAllocateBuffer", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisAllocateBuffer(    Status,    Buffer,    PoolHandle,    VirtualAddress,    Length);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisAllocateBuffer", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisAllocateBuffer(    Status,    Buffer,    PoolHandle,    VirtualAddress,    Length);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisAllocateBuffer", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMInitializeTimer
VOID
S2EHook_NdisMInitializeTimer(
    /* IN */ PNDIS_MINIPORT_TIMER    Timer,
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ PNDIS_TIMER_FUNCTION    TimerFunction,
    /* IN */ PVOID    FunctionContext
)
{



    NdisMInitializeTimer(    Timer,    MiniportAdapterHandle,    TimerFunction,    FunctionContext);
    S2EHook_NdisMInitializeTimer_RegisterEntryPoint(MiniportAdapterHandle, TimerFunction);

    return;


}

//NdisOpenConfigurationKeyByIndex
VOID
S2EHook_NdisOpenConfigurationKeyByIndex(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    ConfigurationHandle,
    /* IN */ ULONG    Index,
    /* OUT */ PNDIS_STRING    KeyName,
    /* OUT */ PNDIS_HANDLE    KeyHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisOpenConfigurationKeyByIndex, "NdisOpenConfigurationKeyByIndex", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisOpenConfigurationKeyByIndex(    Status,    ConfigurationHandle,    Index,    KeyName,    KeyHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisOpenConfigurationKeyByIndex", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisOpenConfigurationKeyByIndex(    Status,    ConfigurationHandle,    Index,    KeyName,    KeyHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisOpenConfigurationKeyByIndex", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMRegisterInterrupt
NDIS_STATUS
S2EHook_NdisMRegisterInterrupt(
    /* OUT */ PNDIS_MINIPORT_INTERRUPT    Interrupt,
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ UINT    InterruptVector,
    /* IN */ UINT    InterruptLevel,
    /* IN */ BOOLEAN    RequestIsr,
    /* IN */ BOOLEAN    SharedInterrupt,
    /* IN */ NDIS_INTERRUPT_MODE    InterruptMode
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMRegisterInterrupt, "NdisMRegisterInterrupt", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMRegisterInterrupt(    Interrupt,    MiniportAdapterHandle,    InterruptVector,    InterruptLevel,    RequestIsr,    SharedInterrupt,    InterruptMode);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMRegisterInterrupt", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMRegisterInterrupt(    Interrupt,    MiniportAdapterHandle,    InterruptVector,    InterruptLevel,    RequestIsr,    SharedInterrupt,    InterruptMode);
        S2EMessageFmt("%s returned %#x\n", "NdisMRegisterInterrupt", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMRegisterInterrupt", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_RESOURCE_CONFLICT,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisMAllocateSharedMemory
VOID
S2EHook_NdisMAllocateSharedMemory(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ ULONG    Length,
    /* IN */ BOOLEAN    Cached,
    /* OUT */ PVOID*    VirtualAddress,
    /* OUT */ PNDIS_PHYSICAL_ADDRESS    PhysicalAddress
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMAllocateSharedMemory, "NdisMAllocateSharedMemory", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisMAllocateSharedMemory(    MiniportAdapterHandle,    Length,    Cached,    VirtualAddress,    PhysicalAddress);
        {
            if (*VirtualAddress) {
                S2ERegisterDmaRegion(PhysicalAddress->QuadPart, Length);
            }
        }

        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMAllocateSharedMemory", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisMAllocateSharedMemory(    MiniportAdapterHandle,    Length,    Cached,    VirtualAddress,    PhysicalAddress);
        {
            if (*VirtualAddress) {
                S2ERegisterDmaRegion(PhysicalAddress->QuadPart, Length);
            }
        }

        return;
    } else {
        S2EIncrementFaultCount();
        *VirtualAddress = NULL;
    }
}

//NdisCmRegisterAddressFamily
NDIS_STATUS
S2EHook_NdisCmRegisterAddressFamily(
    /* IN */ NDIS_HANDLE    NdisBindingHandle,
    /* IN */ PCO_ADDRESS_FAMILY    AddressFamily,
    /* IN */ PNDIS_CALL_MANAGER_CHARACTERISTICS    CmCharacteristics,
    /* IN */ UINT    SizeOfCmCharacteristics
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisCmRegisterAddressFamily, "NdisCmRegisterAddressFamily", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisCmRegisterAddressFamily(    NdisBindingHandle,    AddressFamily,    CmCharacteristics,    SizeOfCmCharacteristics);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisCmRegisterAddressFamily", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisCmRegisterAddressFamily(    NdisBindingHandle,    AddressFamily,    CmCharacteristics,    SizeOfCmCharacteristics);
        S2EMessageFmt("%s returned %#x\n", "NdisCmRegisterAddressFamily", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisCmRegisterAddressFamily", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 2,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

//NdisAllocatePacketPoolEx
VOID
S2EHook_NdisAllocatePacketPoolEx(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_HANDLE    PoolHandle,
    /* IN */ UINT    NumberOfDescriptors,
    /* IN */ UINT    NumberOfOverflowDescriptors,
    /* IN */ UINT    ProtocolReservedLength
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisAllocatePacketPoolEx, "NdisAllocatePacketPoolEx", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisAllocatePacketPoolEx(    Status,    PoolHandle,    NumberOfDescriptors,    NumberOfOverflowDescriptors,    ProtocolReservedLength);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisAllocatePacketPoolEx", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisAllocatePacketPoolEx(    Status,    PoolHandle,    NumberOfDescriptors,    NumberOfOverflowDescriptors,    ProtocolReservedLength);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisAllocatePacketPoolEx", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisMSetMiniportSecondary
NDIS_STATUS
S2EHook_NdisMSetMiniportSecondary(
    /* IN */ NDIS_HANDLE    MiniportAdapterHandle,
    /* IN */ NDIS_HANDLE    PrimaryMiniportAdapterHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMSetMiniportSecondary, "NdisMSetMiniportSecondary", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMSetMiniportSecondary(    MiniportAdapterHandle,    PrimaryMiniportAdapterHandle);
        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMSetMiniportSecondary", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMSetMiniportSecondary(    MiniportAdapterHandle,    PrimaryMiniportAdapterHandle);
        S2EMessageFmt("%s returned %#x\n", "NdisMSetMiniportSecondary", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_FAILURE, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMSetMiniportSecondary", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

/* 44 hooks */
const S2E_HOOK g_NdisMiniportHooks[] = {

    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisAllocateBuffer", (UINT_PTR) S2EHook_NdisAllocateBuffer}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisAllocateMemory", (UINT_PTR) S2EHook_NdisAllocateMemory}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisAllocateMemoryWithTag", (UINT_PTR) S2EHook_NdisAllocateMemoryWithTag}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisAllocatePacket", (UINT_PTR) S2EHook_NdisAllocatePacket}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisAllocatePacketPool", (UINT_PTR) S2EHook_NdisAllocatePacketPool}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisAllocatePacketPoolEx", (UINT_PTR) S2EHook_NdisAllocatePacketPoolEx}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisClDeregisterSap", (UINT_PTR) S2EHook_NdisClDeregisterSap},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisCmRegisterAddressFamily", (UINT_PTR) S2EHook_NdisCmRegisterAddressFamily},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisCoCreateVc", (UINT_PTR) S2EHook_NdisCoCreateVc},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisCoDeleteVc", (UINT_PTR) S2EHook_NdisCoDeleteVc},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisCopyBuffer", (UINT_PTR) S2EHook_NdisCopyBuffer}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisDprAllocatePacket", (UINT_PTR) S2EHook_NdisDprAllocatePacket}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisDprAllocatePacketNonInterlocked", (UINT_PTR) S2EHook_NdisDprAllocatePacketNonInterlocked}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisFreeMemory", (UINT_PTR) S2EHook_NdisFreeMemory},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisIMDeInitializeDeviceInstance", (UINT_PTR) S2EHook_NdisIMDeInitializeDeviceInstance},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisIMRegisterLayeredMiniport", (UINT_PTR) S2EHook_NdisIMRegisterLayeredMiniport}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisInitializeWrapper", (UINT_PTR) S2EHook_NdisInitializeWrapper},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMAllocateMapRegisters", (UINT_PTR) S2EHook_NdisMAllocateMapRegisters},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMAllocateSharedMemory", (UINT_PTR) S2EHook_NdisMAllocateSharedMemory},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMAllocateSharedMemoryAsync", (UINT_PTR) S2EHook_NdisMAllocateSharedMemoryAsync},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMCmCreateVc", (UINT_PTR) S2EHook_NdisMCmCreateVc}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMCmRegisterAddressFamily", (UINT_PTR) S2EHook_NdisMCmRegisterAddressFamily},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMCreateLog", (UINT_PTR) S2EHook_NdisMCreateLog}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMFreeSharedMemory", (UINT_PTR) S2EHook_NdisMFreeSharedMemory},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMIndicateStatus", (UINT_PTR) S2EHook_NdisMIndicateStatus},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMInitializeScatterGatherDma", (UINT_PTR) S2EHook_NdisMInitializeScatterGatherDma},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMInitializeTimer", (UINT_PTR) S2EHook_NdisMInitializeTimer},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMMapIoSpace", (UINT_PTR) S2EHook_NdisMMapIoSpace}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMPromoteMiniport", (UINT_PTR) S2EHook_NdisMPromoteMiniport},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMQueryAdapterResources", (UINT_PTR) S2EHook_NdisMQueryAdapterResources}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMRegisterInterrupt", (UINT_PTR) S2EHook_NdisMRegisterInterrupt}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMRegisterIoPortRange", (UINT_PTR) S2EHook_NdisMRegisterIoPortRange}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMRegisterMiniport", (UINT_PTR) S2EHook_NdisMRegisterMiniport},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMRemoveMiniport", (UINT_PTR) S2EHook_NdisMRemoveMiniport},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMSendComplete", (UINT_PTR) S2EHook_NdisMSendComplete},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMSetMiniportSecondary", (UINT_PTR) S2EHook_NdisMSetMiniportSecondary},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMWriteLogData", (UINT_PTR) S2EHook_NdisMWriteLogData},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisOpenConfiguration", (UINT_PTR) S2EHook_NdisOpenConfiguration}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisOpenConfigurationKeyByIndex", (UINT_PTR) S2EHook_NdisOpenConfigurationKeyByIndex}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisOpenConfigurationKeyByName", (UINT_PTR) S2EHook_NdisOpenConfigurationKeyByName}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisReadConfiguration", (UINT_PTR) S2EHook_NdisReadConfiguration}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisReadNetworkAddress", (UINT_PTR) S2EHook_NdisReadNetworkAddress}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisWriteConfiguration", (UINT_PTR) S2EHook_NdisWriteConfiguration},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisWriteEventLogEntry", (UINT_PTR) S2EHook_NdisWriteEventLogEntry},
    {0,0,0}

};

/**

 * 35 functions that have one status and other output arguments:
 * -------------------------------------------
 * NdisAllocateBuffer [IN=3 OUT=2]
 * NdisAllocateBufferPool [IN=1 OUT=2]
 * NdisAllocateMemory [IN=3 OUT=1]
 * NdisAllocateMemoryWithTag [IN=2 OUT=1]
 * NdisAllocatePacket [IN=1 OUT=2]
 * NdisAllocatePacketPool [IN=2 OUT=2]
 * NdisAllocatePacketPoolEx [IN=3 OUT=2]
 * NdisClAddParty [IN=3 OUT=1]
 * NdisClMakeCall [IN=3 OUT=1]
 * NdisClOpenAddressFamily [IN=5 OUT=1]
 * NdisClRegisterSap [IN=3 OUT=1]
 * NdisCopyBuffer [IN=4 OUT=2]
 * NdisDprAllocatePacket [IN=1 OUT=2]
 * NdisDprAllocatePacketNonInterlocked [IN=1 OUT=2]
 * NdisIMRegisterLayeredMiniport [IN=3 OUT=1]
 * NdisMCmCreateVc [IN=3 OUT=1]
 * NdisMCreateLog [IN=2 OUT=1]
 * NdisMMapIoSpace [IN=3 OUT=1]
 * NdisMQueryAdapterInstanceName [IN=1 OUT=1]
 * NdisMQueryAdapterResources [IN=2 OUT=2]
 * NdisMRegisterDevice [IN=4 OUT=2]
 * NdisMRegisterInterrupt [IN=6 OUT=1]
 * NdisMRegisterIoPortRange [IN=3 OUT=1]
 * NdisOpenAdapter [IN=7 OUT=4]
 * NdisOpenConfiguration [IN=1 OUT=2]
 * NdisOpenConfigurationKeyByIndex [IN=2 OUT=3]
 * NdisOpenConfigurationKeyByName [IN=2 OUT=2]
 * NdisOpenProtocolConfiguration [IN=1 OUT=2]
 * NdisQueryAdapterInstanceName [IN=1 OUT=1]
 * NdisReadConfiguration [IN=3 OUT=2]
 * NdisReadEisaSlotInformation [IN=1 OUT=3]
 * NdisReadEisaSlotInformationEx [IN=1 OUT=4]
 * NdisReadNetworkAddress [IN=1 OUT=3]
 * NdisRegisterProtocol [IN=2 OUT=2]
 * NdisTransferData [IN=5 OUT=2]
 *
 * 96 functions do not return a status code:
 * -------------------------------------------
 * NDIS_BUFFER_TO_SPAN_PAGES
 * NdisAcquireReadWriteLock
 * NdisAdjustBufferLength
 * NdisBufferLength
 * NdisBufferVirtualAddress
 * NdisClIncomingCallComplete
 * NdisCloseConfiguration
 * NdisCmAddPartyComplete
 * NdisCmCloseAddressFamilyComplete
 * NdisCmCloseCallComplete
 * NdisCmDeregisterSapComplete
 * NdisCmDispatchCallConnected
 * NdisCmDispatchIncomingCallQoSChange
 * NdisCmDispatchIncomingCloseCall
 * NdisCmDispatchIncomingDropParty
 * NdisCmDropPartyComplete
 * NdisCmMakeCallComplete
 * NdisCmModifyCallQoSComplete
 * NdisCmOpenAddressFamilyComplete
 * NdisCmRegisterSapComplete
 * NdisCoRequestComplete
 * NdisCoSendPackets
 * NdisCompleteBindAdapter
 * NdisCompletePnPEvent
 * NdisCompleteUnbindAdapter
 * NdisCopyFromPacketToPacket [IN=5 OUT=1]
 * NdisDprFreePacket
 * NdisDprFreePacketNonInterlocked
 * NdisFreeBuffer
 * NdisFreeBufferPool
 * NdisFreeMemory
 * NdisFreePacket
 * NdisFreePacketPool
 * NdisGetBufferPhysicalArraySize [IN=1 OUT=1]
 * NdisGetCurrentProcessorCounts [IN=0 OUT=3]
 * NdisGetCurrentProcessorCpuUsage
 * NdisGetDriverHandle [IN=1 OUT=1]
 * NdisGetFirstBufferFromPacket [IN=1 OUT=4]
 * NdisGetReceivedPacket
 * NdisIMAssociateMiniport
 * NdisIMCopySendCompletePerPacketInfo
 * NdisIMCopySendPerPacketInfo
 * NdisIMDeregisterLayeredMiniport
 * NdisIMGetBindingContext
 * NdisIMGetDeviceContext
 * NdisImmediateReadSharedMemory
 * NdisImmediateWriteSharedMemory
 * NdisInitializeReadWriteLock
 * NdisInitializeWrapper
 * NdisMAllocateSharedMemory [IN=3 OUT=2]
 * NdisMCancelTimer [IN=1 OUT=1]
 * NdisMCloseLog
 * NdisMCoActivateVcComplete
 * NdisMCoDeactivateVcComplete
 * NdisMCoIndicateReceivePacket
 * NdisMCoIndicateStatus
 * NdisMCoReceiveComplete
 * NdisMCoRequestComplete
 * NdisMCoSendComplete
 * NdisMDeregisterAdapterShutdownHandler
 * NdisMDeregisterInterrupt
 * NdisMDeregisterIoPortRange
 * NdisMFlushLog
 * NdisMFreeMapRegisters
 * NdisMFreeSharedMemory
 * NdisMGetDeviceProperty
 * NdisMIndicateStatus
 * NdisMInitializeTimer
 * NdisMRegisterAdapterShutdownHandler
 * NdisMRegisterUnloadHandler
 * NdisMSendComplete
 * NdisMSetAttributesEx
 * NdisMSetPeriodicTimer
 * NdisMSleep
 * NdisMSynchronizeWithInterrupt
 * NdisMUnmapIoSpace
 * NdisMWanIndicateReceiveComplete
 * NdisMWanSendComplete
 * NdisPacketPoolUsage
 * NdisQueryBuffer [IN=1 OUT=2]
 * NdisQueryBufferOffset [IN=1 OUT=2]
 * NdisQueryBufferSafe [IN=2 OUT=2]
 * NdisReadPciSlotInformation
 * NdisReadPcmciaAttributeMemory
 * NdisReleaseReadWriteLock
 * NdisReturnPackets
 * NdisSendPackets
 * NdisSetPacketPoolProtocolId
 * NdisTerminateWrapper
 * NdisUnchainBufferAtBack [IN=1 OUT=1]
 * NdisUnchainBufferAtFront [IN=1 OUT=1]
 * NdisUpcaseUnicodeString [IN=1 OUT=1]
 * NdisUpdateSharedMemory
 * NdisWriteErrorLogEntry
 * NdisWritePciSlotInformation
 * NdisWritePcmciaAttributeMemory
 *
 * 8 functions return a status code but have no codes defined:
 * ------------------------------------------------------------------
 * NdisAllocateBufferPool [IN=1 OUT=2]
 * NdisIMCancelInitializeDeviceInstance
 * NdisMDeregisterDevice
 * NdisMQueryAdapterInstanceName [IN=1 OUT=1]
 * NdisMQueryAdapterResources [IN=2 OUT=2]
 * NdisMRegisterDevice [IN=4 OUT=2]
 * NdisQueryAdapterInstanceName [IN=1 OUT=1]
 * NdisSetupDmaTransfer
 *
 * 22 functions only have success codes:
 * ---------------------------------------
 * NdisAnsiStringToUnicodeString ['NDIS_STATUS_SUCCESS']
 * NdisClAddParty ['NDIS_STATUS_PENDING'] [IN=3 OUT=1]
 * NdisClCloseAddressFamily ['NDIS_STATUS_PENDING']
 * NdisClCloseCall ['NDIS_STATUS_PENDING']
 * NdisClDropParty ['NDIS_STATUS_PENDING']
 * NdisClMakeCall ['NDIS_STATUS_PENDING'] [IN=3 OUT=1]
 * NdisClModifyCallQoS ['NDIS_STATUS_PENDING']
 * NdisClOpenAddressFamily ['NDIS_STATUS_PENDING'] [IN=5 OUT=1]
 * NdisClRegisterSap ['NDIS_STATUS_PENDING'] [IN=3 OUT=1]
 * NdisCloseAdapter ['NDIS_STATUS_SUCCESS', 'NDIS_STATUS_PENDING'] [IN=1 OUT=1]
 * NdisCmActivateVc ['NDIS_STATUS_PENDING']
 * NdisCmDeactivateVc ['NDIS_STATUS_PENDING']
 * NdisCmDispatchIncomingCall ['NDIS_STATUS_PENDING']
 * NdisCoRequest ['NDIS_STATUS_PENDING']
 * NdisIMInitializeDeviceInstanceEx ['NDIS_STATUS_SUCCESS', 'NDIS_STATUS_NOT_ACCEPTED']
 * NdisMCmActivateVc ['NDIS_STATUS_PENDING']
 * NdisMCmDeactivateVc ['NDIS_STATUS_SUCCESS', 'NDIS_STATUS_NOT_ACCEPTED']
 * NdisMCmDeleteVc ['NDIS_STATUS_SUCCESS', 'NDIS_STATUS_NOT_ACCEPTED']
 * NdisMCmRequest ['NDIS_STATUS_PENDING']
 * NdisMWanIndicateReceive ['NDIS_STATUS_SUCCESS', 'NDIS_STATUS_NOT_ACCEPTED'] [IN=4 OUT=1]
 * NdisOpenProtocolConfiguration ['NDIS_STATUS_SUCCESS'] [IN=1 OUT=2]
 * NdisUnicodeStringToAnsiString ['NDIS_STATUS_SUCCESS']
**/

