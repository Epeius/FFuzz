#include <ndis.h>
#include <ntdef.h>

#include "s2e.h"
#include "symbhw.h"
#include "hook.h"
#include <ResourceTracker.h>

#include "winxp-ndis-protocol-custom.h"
//NdisReadEisaSlotInformation is obsolete, skipping


//NdisDeregisterProtocol
VOID
S2EHook_NdisDeregisterProtocol(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    NdisProtocolHandle
)
{



    NdisDeregisterProtocol(    Status,    NdisProtocolHandle);
    if (NT_SUCCESS(*Status)) {
        S2EHook_NdisDeregisterProtocol_DeregisterEntryPoints(Status, NdisProtocolHandle);
    }

    return;


}

//NdisRegisterProtocol
VOID
S2EHook_NdisRegisterProtocol(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_HANDLE    NdisProtocolHandle,
    /* IN */ PNDIS_PROTOCOL_CHARACTERISTICS    ProtocolCharacteristics,
    /* IN */ UINT    CharacteristicsLength
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisRegisterProtocol, "NdisRegisterProtocol", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisRegisterProtocol(    Status,    NdisProtocolHandle,    ProtocolCharacteristics,    CharacteristicsLength);
        if (NT_SUCCESS(*Status)) {
            S2EHook_NdisRegisterProtocol_RegisterEntryPoints(Status, NdisProtocolHandle, ProtocolCharacteristics, CharacteristicsLength);
        }

        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisRegisterProtocol", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisRegisterProtocol(    Status,    NdisProtocolHandle,    ProtocolCharacteristics,    CharacteristicsLength);
        if (NT_SUCCESS(*Status)) {
            S2EHook_NdisRegisterProtocol_RegisterEntryPoints(Status, NdisProtocolHandle, ProtocolCharacteristics, CharacteristicsLength);
        }

        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisRegisterProtocol", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_BAD_CHARACTERISTICS,    NDIS_STATUS_BAD_VERSION);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisTransferData is obsolete, skipping


//NdisOpenAdapter
VOID
S2EHook_NdisOpenAdapter(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_STATUS    OpenErrorStatus,
    /* OUT */ PNDIS_HANDLE    NdisBindingHandle,
    /* OUT */ PUINT    SelectedMediumIndex,
    /* IN */ PNDIS_MEDIUM    MediumArray,
    /* IN */ UINT    MediumArraySize,
    /* IN */ NDIS_HANDLE    NdisProtocolHandle,
    /* IN */ NDIS_HANDLE    ProtocolBindingContext,
    /* IN */ PNDIS_STRING    AdapterName,
    /* IN */ UINT    OpenOptions,
    /* IN */ PSTRING    AddressingInformation
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisOpenAdapter, "NdisOpenAdapter", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisOpenAdapter(    Status,    OpenErrorStatus,    NdisBindingHandle,    SelectedMediumIndex,    MediumArray,    MediumArraySize,    NdisProtocolHandle,    ProtocolBindingContext,    AdapterName,    OpenOptions,    AddressingInformation);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisOpenAdapter", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisOpenAdapter(    Status,    OpenErrorStatus,    NdisBindingHandle,    SelectedMediumIndex,    MediumArray,    MediumArraySize,    NdisProtocolHandle,    ProtocolBindingContext,    AdapterName,    OpenOptions,    AddressingInformation);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_ADAPTER_NOT_FOUND, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisOpenAdapter", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 5,    NDIS_STATUS_ADAPTER_NOT_FOUND,    NDIS_STATUS_OPEN_FAILED,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_UNSUPPORTED_MEDIA,    NDIS_STATUS_CLOSING);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisReset
VOID
S2EHook_NdisReset(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    NdisBindingHandle
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisReset, "NdisReset", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisReset(    Status,    NdisBindingHandle);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisReset", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisReset(    Status,    NdisBindingHandle);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESET_IN_PROGRESS, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisReset", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 7,    NDIS_STATUS_RESET_IN_PROGRESS,    NDIS_STATUS_SOFT_ERRORS,    NDIS_STATUS_HARD_ERRORS,    NDIS_STATUS_NOT_RESETTABLE,    NDIS_STATUS_CLOSING,    NDIS_STATUS_ADAPTER_REMOVED,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisRequest
VOID
S2EHook_NdisRequest(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    NdisBindingHandle,
    /* IN */ PNDIS_REQUEST    NdisRequest2
)
{

    /* Variable declarations */INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisRequest, "NdisRequest", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        NdisRequest(    Status,    NdisBindingHandle,    NdisRequest2);
        return;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisRequest", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        NdisRequest(    Status,    NdisBindingHandle,    NdisRequest2);
        return;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_INVALID_OID, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisRequest", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 10,    NDIS_STATUS_INVALID_OID,    NDIS_STATUS_RESET_IN_PROGRESS,    NDIS_STATUS_CLOSING,    NDIS_STATUS_CLOSING_INDICATING,    NDIS_STATUS_FAILURE,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_BUFFER_TOO_SHORT,    NDIS_STATUS_INVALID_DATA,    NDIS_STATUS_INVALID_LENGTH,    NDIS_STATUS_NOT_SUPPORTED);
        S2EEndAtomic();

        *Status = ConcolicStatus;
    }
}

//NdisReadEisaSlotInformationEx is obsolete, skipping


//NdisSend is obsolete, skipping


/* 5 hooks */
const S2E_HOOK g_NdisProtocolHooks[] = {

    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisDeregisterProtocol", (UINT_PTR) S2EHook_NdisDeregisterProtocol},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisOpenAdapter", (UINT_PTR) S2EHook_NdisOpenAdapter}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisRegisterProtocol", (UINT_PTR) S2EHook_NdisRegisterProtocol}, /* multiple outputs */
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisRequest", (UINT_PTR) S2EHook_NdisRequest},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisReset", (UINT_PTR) S2EHook_NdisReset},
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
 * 0 functions do not return a status code:
 * -------------------------------------------
 *
 * 0 functions return a status code but have no codes defined:
 * ------------------------------------------------------------------
 *
 * 1 functions only have success codes:
 * ---------------------------------------
 * NdisDeregisterProtocol ['NDIS_STATUS_SUCCESS'] [IN=1 OUT=1]
**/

