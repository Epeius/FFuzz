#define NDIS_MINIPORT_DRIVER
#define NDIS60_MINIPORT 1

#include <ndis.h>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <hook.h>
#include <keyvalue.h>
#include <searcher.h>
#include <symbhw.h>
#include <s2e.h>

#include "apihooks.h"



static NDIS_STATUS S2EHook_ndis_SetOptionsHandler(
  MINIPORT_SET_OPTIONS Original,
  /* _In_ */ NDIS_HANDLE NdisDriverHandle,
  /* _In_ */ NDIS_HANDLE DriverContext
);

static NDIS_STATUS S2EHook_ndis_InitializeHandlerEx (
    MINIPORT_INITIALIZE_HANDLER Original,
    /* _In_ */ NDIS_HANDLE                         NdisMiniportHandle,
    /* _In_ */ NDIS_HANDLE                         MiniportDriverContext,
    /* _In_ */ PNDIS_MINIPORT_INIT_PARAMETERS      MiniportInitParameters
);

static VOID S2EHook_ndis_HaltHandlerEx(
    MINIPORT_HALT   Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  NDIS_HALT_ACTION        HaltAction
);

static VOID S2EHook_ndis_UnloadHandler (
    MINIPORT_UNLOAD Original,
    /* _In_ */ PDRIVER_OBJECT           DriverObject
);

static NDIS_STATUS S2EHook_ndis_PauseHandler(
    MINIPORT_PAUSE_HANDLER  Original,
    /* _In_ */  NDIS_HANDLE MiniportAdapterContext,
    /* _In_ */  PNDIS_MINIPORT_PAUSE_PARAMETERS   PauseParameters
);

static NDIS_STATUS S2EHook_ndis_RestartHandler(
    MINIPORT_RESTART_HANDLER Original,
    /* _In_ */  NDIS_HANDLE  MiniportAdapterContext,
    /* _In_ */  PNDIS_MINIPORT_RESTART_PARAMETERS       RestartParameters
);

static NDIS_STATUS S2EHook_ndis_OidRequestHandler (
    MINIPORT_OID_REQUEST_HANDLER Original,
    /* _In_ */  NDIS_HANDLE      MiniportAdapterContext,
    /* _In_ */  PNDIS_OID_REQUEST OidRequest
);

static VOID S2EHook_ndis_SendNetBufferListsHandler(
    MINIPORT_SEND_NET_BUFFER_LISTS Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PNET_BUFFER_LIST        NetBufferList,
    /* _In_ */  NDIS_PORT_NUMBER        PortNumber,
    /* _In_ */  ULONG                   SendFlags
);

static VOID S2EHook_ndis_ReturnNetBufferListsHandler(
    MINIPORT_RETURN_NET_BUFFER_LISTS Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PNET_BUFFER_LIST        NetBufferLists,
    /* _In_ */  ULONG                   ReturnFlags
);

static VOID S2EHook_ndis_CancelSendHandler(
    MINIPORT_CANCEL_SEND Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PVOID                   CancelId
);

static BOOLEAN S2EHook_ndis_CheckForHangHandlerEx(
    MINIPORT_CHECK_FOR_HANG Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext
);

static NDIS_STATUS S2EHook_ndis_ResetHandlerEx(
    MINIPORT_RESET Original,
    /* _In_ */   NDIS_HANDLE             MiniportAdapterContext,
    /* _Out_ */ PBOOLEAN                AddressingReset
);

static VOID S2EHook_ndis_DevicePnPEventNotifyHandler (
    MINIPORT_DEVICE_PNP_EVENT_NOTIFY Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
);

static VOID S2EHook_ndis_ShutdownHandlerEx (
    MINIPORT_SHUTDOWN Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  NDIS_SHUTDOWN_ACTION    ShutdownAction
);

static VOID S2EHook_ndis_CancelOidRequestHandler(
    MINIPORT_CANCEL_OID_REQUEST Original,
    /* _In_ */ NDIS_HANDLE      MiniportAdapterContext,
    /* _In_ */ PVOID            RequestId
);


VOID S2EHook_NdisMRegisterMiniportDriver_RegisterEntryPoints(
  /* _In_     */ PDRIVER_OBJECT DriverObject,
  /* _In_     */ PUNICODE_STRING RegistryPath,
  /* _In_opt_ */ NDIS_HANDLE MiniportDriverContext,
  /* _In_     */ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
  /* _Out_    */ PNDIS_HANDLE NdisMiniportDriverHandle
)
{
    if (MiniportDriverCharacteristics->MajorNdisVersion < 6) {
        S2EMessageFmt("%s bad version %x\n", __FUNCTION__, MiniportDriverCharacteristics->MajorNdisVersion);
        return;
    }

    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, InitializeHandlerEx);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, SetOptionsHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, HaltHandlerEx);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, UnloadHandler);

    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, PauseHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, RestartHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, OidRequestHandler);

    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, SendNetBufferListsHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, ReturnNetBufferListsHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, CancelSendHandler);

    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, CheckForHangHandlerEx);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, ResetHandlerEx);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, DevicePnPEventNotifyHandler);

    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, ShutdownHandlerEx);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisMiniportDriverHandle, MiniportDriverCharacteristics, CancelOidRequestHandler);

    //TODO: Ndis 6.1 handlers
}

/**************************************************************/

static NDIS_STATUS S2EHook_ndis_SetOptionsHandler(
  MINIPORT_SET_OPTIONS Original,
  /* _In_ */ NDIS_HANDLE NdisDriverHandle,
  /* _In_ */ NDIS_HANDLE DriverContext
)
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(NdisDriverHandle, DriverContext);

    //XXX: Is the driver always unloaded ?
    //XXX: avoid code duplication
    if (Result != NDIS_STATUS_SUCCESS) {
        if (S2EGetPathCount() > 1) {
            S2EDriverExerciserKillState(Result, "ENTRY POINT SetOptionsHandler failed");
        } else {
            BOOLEAN NewKey;
            S2EMessage("ENTRY POINT SetOptionsHandler failed while in last state");
            //S2EKVSSetValue("all_failed", 1, &NewKey);
            SymbhwNotifyTestScriptToLoadNextConfig();
            SymbHwActivateSymbolicPciBus(FALSE);
        }
    }

    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static NDIS_STATUS S2EHook_ndis_InitializeHandlerEx (
    MINIPORT_INITIALIZE_HANDLER Original,
    /* _In_ */ NDIS_HANDLE                         NdisMiniportHandle,
    /* _In_ */ NDIS_HANDLE                         MiniportDriverContext,
    /* _In_ */ PNDIS_MINIPORT_INIT_PARAMETERS      MiniportInitParameters
)
{
    NDIS_STATUS Result;
    //TODO: check that this is valid on Ndis 6
    NDIS_MINIPORT_BLOCK *Block = (NDIS_MINIPORT_BLOCK *) NdisMiniportHandle;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);

    //Registering internal APIs
    //TODO: make these work
    //REGISTER_NDIS_LIBRARY_HOOK(Original, MiniportDriverContext, Block, StatusHandler);
    //REGISTER_NDIS_LIBRARY_HOOK(Original, MiniportDriverContext, Block, SendCompleteHandler);

    SymbHwActivateSymbolicPciBus(TRUE);

    Result = Original(NdisMiniportHandle, MiniportDriverContext,
             MiniportInitParameters);

    S2EPrintExpression(Result, "Result");

    if (Result != NDIS_STATUS_SUCCESS) {
        if (S2EGetPathCount() > 1) {
            S2EDriverExerciserKillState(Result, "ENTRY POINT InitializeHandlerEx failed");
        } else {
            S2EMessage("ENTRY POINT InitializeHandlerEx failed while in last state");
            SymbhwNotifyTestScriptOfFailure();
        }
    }

    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    S2ESearcherPopContext();
    return Result;
}


static VOID S2EHook_ndis_HaltHandlerEx(
    MINIPORT_HALT   Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  NDIS_HALT_ACTION        HaltAction
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, HaltAction);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    //TODO: check if it's the last path
    S2EDriverExerciserKillState(0, "S2EHook_ndis_HaltHandlerEx called");
}

static VOID S2EHook_ndis_UnloadHandler (
    MINIPORT_UNLOAD Original,
    /* _In_ */ PDRIVER_OBJECT           DriverObject
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(DriverObject);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    if (S2EGetInjectedFaultCount() == 0) {
        //XXX: don't do that if the driver successfully loaded
        S2EMessageFmt("No faults in this path, will try another hw config\n");
        SymbhwNotifyTestScriptToLoadNextConfig();
        SymbHwActivateSymbolicPciBus(FALSE);
    }

    S2EDriverExerciserKillState(0, "S2EHook_ndis_UnloadHandler called");
}

static NDIS_STATUS S2EHook_ndis_PauseHandler(
    MINIPORT_PAUSE_HANDLER  Original,
    /* _In_ */  NDIS_HANDLE MiniportAdapterContext,
    /* _In_ */  PNDIS_MINIPORT_PAUSE_PARAMETERS   PauseParameters
)
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAdapterContext, PauseParameters);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static NDIS_STATUS S2EHook_ndis_RestartHandler(
    MINIPORT_RESTART_HANDLER Original,
    /* _In_ */  NDIS_HANDLE  MiniportAdapterContext,
    /* _In_ */  PNDIS_MINIPORT_RESTART_PARAMETERS       RestartParameters
)
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAdapterContext, RestartParameters);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static NDIS_STATUS S2EHook_ndis_OidRequestHandler (
    MINIPORT_OID_REQUEST_HANDLER Original,
    /* _In_ */  NDIS_HANDLE      MiniportAdapterContext,
    /* _In_ */  PNDIS_OID_REQUEST OidRequest
)
{
    NDIS_STATUS Result;

    //TODO: handle connection status
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);

    switch (OidRequest->RequestType) {
        case NdisRequestQueryInformation: {
            S2EMessageFmt("NdisRequestQueryInformation\n");
            S2EPrintExpression(OidRequest->DATA.QUERY_INFORMATION.Oid, "OID");
        } break;
        case NdisRequestSetInformation: {
            S2EMessageFmt("NdisRequestSetInformation\n");
            S2EPrintExpression(OidRequest->DATA.QUERY_INFORMATION.Oid, "OID");
        } break;
        default: {
            S2EMessageFmt("Request id %#x\n", OidRequest->RequestType);
        } break;
    }

    Result = Original(MiniportAdapterContext, OidRequest);

    if (OidRequest->RequestType == NdisRequestQueryInformation) {
        if (OidRequest->DATA.QUERY_INFORMATION.Oid == OID_GEN_MEDIA_CONNECT_STATUS) {
            NDIS_MEDIA_STATE *State = (NDIS_MEDIA_STATE*) OidRequest->DATA.QUERY_INFORMATION.InformationBuffer;
            if (*State == NdisMediaStateDisconnected) {
                //XXX: Depreioritize instead?
                S2EKillState(0, "Killing because network cable is disconnected\n");
            }
        }
    }


    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static VOID S2EHook_ndis_SendNetBufferListsHandler(
    MINIPORT_SEND_NET_BUFFER_LISTS Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PNET_BUFFER_LIST        NetBufferList,
    /* _In_ */  NDIS_PORT_NUMBER        PortNumber,
    /* _In_ */  ULONG                   SendFlags
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, NetBufferList, PortNumber, SendFlags);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_ReturnNetBufferListsHandler(
    MINIPORT_RETURN_NET_BUFFER_LISTS Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PNET_BUFFER_LIST        NetBufferLists,
    /* _In_ */  ULONG                   ReturnFlags
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, NetBufferLists, ReturnFlags);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_CancelSendHandler(
    MINIPORT_CANCEL_SEND Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PVOID                   CancelId
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, CancelId);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static BOOLEAN S2EHook_ndis_CheckForHangHandlerEx(
    MINIPORT_CHECK_FOR_HANG Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext
)
{
    BOOLEAN Result;
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    return Result;
}

static NDIS_STATUS S2EHook_ndis_ResetHandlerEx(
    MINIPORT_RESET Original,
    /* _In_ */   NDIS_HANDLE             MiniportAdapterContext,
    /* _Out_ */ PBOOLEAN                AddressingReset
)
{
    NDIS_STATUS Result;
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAdapterContext, AddressingReset);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    return Result;
}

static VOID S2EHook_ndis_DevicePnPEventNotifyHandler (
    MINIPORT_DEVICE_PNP_EVENT_NOTIFY Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, NetDevicePnPEvent);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_ShutdownHandlerEx (
    MINIPORT_SHUTDOWN Original,
    /* _In_ */  NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */  NDIS_SHUTDOWN_ACTION    ShutdownAction
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, ShutdownAction);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_CancelOidRequestHandler(
    MINIPORT_CANCEL_OID_REQUEST Original,
    /* _In_ */ NDIS_HANDLE      MiniportAdapterContext,
    /* _In_ */ PVOID            RequestId
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, RequestId);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}
