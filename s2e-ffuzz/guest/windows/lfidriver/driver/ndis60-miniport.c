//This file will be eventually automatically generated
#define NDIS_MINIPORT_DRIVER

#define NDIS60_MINIPORT

#include <ndis.h>
#include <ntdef.h>

#include "s2e.h"
#include "symbhw.h"
#include "hook.h"

#include "ndis60-miniport-custom.h"

//NdisMRegisterMiniportDriver
NDIS_STATUS
S2EHook_NdisMRegisterMiniportDriver(
    /* _In_     */ PDRIVER_OBJECT DriverObject,
    /* _In_     */ PUNICODE_STRING RegistryPath,
    /* _In_opt_ */ NDIS_HANDLE MiniportDriverContext,
    /* _In_     */ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
    /* _Out_    */ PNDIS_HANDLE NdisMiniportDriverHandle
)
{

    /* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMRegisterMiniportDriver, "NdisMRegisterMiniportDriver", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, MiniportDriverContext, MiniportDriverCharacteristics, NdisMiniportDriverHandle);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisMRegisterMiniportDriver_RegisterEntryPoints(DriverObject, RegistryPath, MiniportDriverContext, MiniportDriverCharacteristics, NdisMiniportDriverHandle);
        }

        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMRegisterMiniportDriver", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, MiniportDriverContext, MiniportDriverCharacteristics, NdisMiniportDriverHandle);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisMRegisterMiniportDriver_RegisterEntryPoints(DriverObject, RegistryPath, MiniportDriverContext, MiniportDriverCharacteristics, NdisMiniportDriverHandle);
        }

        S2EMessageFmt("%s returned %#x\n", "NdisMRegisterMiniportDriver", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMRegisterMiniportDriver", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 4,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_BAD_CHARACTERISTICS,    NDIS_STATUS_BAD_VERSION,    NDIS_STATUS_FAILURE);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

NDIS_STATUS S2EHook_NdisSetOptionalHandlers(
  NDIS_HANDLE NdisHandle,
  PNDIS_DRIVER_OPTIONAL_HANDLERS OptionalHandlers
)
{
/* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisSetOptionalHandlers, "NdisSetOptionalHandlers", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisSetOptionalHandlers(NdisHandle, OptionalHandlers);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisSetOptionalHandlers_RegisterEntryPoints(NdisHandle, OptionalHandlers);
        }

        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisSetOptionalHandlers", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisSetOptionalHandlers(NdisHandle, OptionalHandlers);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisSetOptionalHandlers_RegisterEntryPoints(NdisHandle, OptionalHandlers);
        }

        S2EMessageFmt("%s returned %#x\n", "NdisSetOptionalHandlers", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisSetOptionalHandlers", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 3,    NDIS_STATUS_RESOURCES,    NDIS_STATUS_FAILURE, NDIS_STATUS_NOT_SUPPORTED);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

NDIS_STATUS S2EHook_NdisMRegisterInterruptEx(
  /* _In_ */  NDIS_HANDLE MiniportAdapterHandle,
  /* _In_ */  NDIS_HANDLE MiniportInterruptContext,
  /* _In_ */  PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS MiniportInterruptCharacteristics,
  /* _Out_*/  PNDIS_HANDLE NdisInterruptHandle
)
{
/* Variable declarations */NDIS_STATUS RetVal;
    INT Inject;
    UINT8 InvokeOriginal;
    CHAR CallSiteIdStr[64];
    CHAR SymbolicVarName[128];
    UINT_PTR CallSite = (UINT_PTR) _ReturnAddress();

    Inject = DecideInjectFault((UINT_PTR)&NdisMRegisterInterruptEx, "NdisMRegisterInterruptEx", "ndis.sys", CallSite, CallSiteIdStr, sizeof(CallSiteIdStr));

    if (!Inject) {

        RetVal = NdisMRegisterInterruptEx(MiniportAdapterHandle, MiniportInterruptContext, MiniportInterruptCharacteristics, NdisInterruptHandle);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisMRegisterInterruptEx_RegisterEntryPoints(MiniportAdapterHandle, MiniportInterruptContext, MiniportInterruptCharacteristics, NdisInterruptHandle);
        }

        return RetVal;
    }


    S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_invokeorig_NdisMRegisterInterruptEx", CallSiteIdStr);
    InvokeOriginal = S2EConcolicChar(SymbolicVarName, 1);
    if (InvokeOriginal) {

        RetVal = NdisMRegisterInterruptEx(MiniportAdapterHandle, MiniportInterruptContext, MiniportInterruptCharacteristics, NdisInterruptHandle);
        if (NT_SUCCESS(RetVal)) {
            S2EHook_NdisMRegisterInterruptEx_RegisterEntryPoints(MiniportAdapterHandle, MiniportInterruptContext, MiniportInterruptCharacteristics, NdisInterruptHandle);
        }

        S2EMessageFmt("%s returned %#x\n", "NdisMRegisterInterruptEx", RetVal);
        return RetVal;
    } else {
        NTSTATUS InitialStatus = NDIS_STATUS_RESOURCES, ConcolicStatus;
        S2EIncrementFaultCount();
        S2EBeginAtomic();

        S2EGetSymbolicName(SymbolicVarName, sizeof(SymbolicVarName), "S2EHook_fault_NdisMRegisterInterruptEx", CallSiteIdStr);
        ConcolicStatus = S2EConcolicStatus(SymbolicVarName, InitialStatus);
        S2EAssumeDisjunction(ConcolicStatus, 1,    NDIS_STATUS_RESOURCES);
        S2EEndAtomic();

        return ConcolicStatus;
    }
}

const S2E_HOOK g_Ndis60MiniportHooks[] = {
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMRegisterMiniportDriver", (UINT_PTR) S2EHook_NdisMRegisterMiniportDriver},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisSetOptionalHandlers", (UINT_PTR) S2EHook_NdisSetOptionalHandlers},
    {(UINT_PTR) "ndis.sys", (UINT_PTR) "NdisMRegisterInterruptEx", (UINT_PTR) S2EHook_NdisMRegisterInterruptEx},
    {0,0,0}
};
