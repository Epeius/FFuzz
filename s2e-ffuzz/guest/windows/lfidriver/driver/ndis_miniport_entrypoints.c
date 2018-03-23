#define NDIS_MINIPORT_DRIVER
#define NDIS51_MINIPORT 1

#include <ndis.h>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <hook.h>
#include <keyvalue.h>
#include <searcher.h>
#include <symbhw.h>
#include <s2e.h>
#include "apihooks.h"
#include <ResourceTracker.h>

static BOOLEAN
S2EHook_ndis_CheckForHangHandler(
    W_CHECK_FOR_HANG_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
);

static VOID
S2EHook_ndis_DisableInterruptHandler(
    W_DISABLE_INTERRUPT_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
);

static VOID
S2EHook_ndis_EnableInterruptHandler(
    W_DISABLE_INTERRUPT_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
);

static VOID
S2EHook_ndis_HaltHandler(
    W_HALT_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
);

static VOID
S2EHook_ndis_HandleInterruptHandler(
    W_HANDLE_INTERRUPT_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
);

static NDIS_STATUS S2EHook_ndis_InitializeHandler(
    W_INITIALIZE_HANDLER Original,
    PNDIS_STATUS            OpenErrorStatus,
    PUINT                   SelectedMediumIndex,
    PNDIS_MEDIUM            MediumArray,
    UINT                    MediumArraySize,
    NDIS_HANDLE             MiniportAdapterContext,
    NDIS_HANDLE             WrapperConfigurationContext);

static VOID
S2EHook_ndis_ISRHandler(
    W_ISR_HANDLER Original,
    PBOOLEAN      InterruptRecognized,
    PBOOLEAN      QueueMiniportHandleInterrupt,
    NDIS_HANDLE   MiniportAdapterContext
);


static NDIS_STATUS
S2EHook_ndis_QueryInformationHandler(
    W_QUERY_INFORMATION_HANDLER Original,
    /* _In_ */  NDIS_HANDLE     MiniportAdapterContext,
    /* _In_ */  NDIS_OID        Oid,
    /* _In_ */  PVOID           InformationBuffer,
    /* _In_ */  ULONG           InformationBufferLength,
    /* _Out_*/  PULONG          BytesWritten,
    /* _Out_*/  PULONG          BytesNeeded
);

static NDIS_STATUS
S2EHook_ndis_ReconfigureHandler(
    W_RECONFIGURE_HANDLER Original,
    PNDIS_STATUS    OpenErrorStatus,
    NDIS_HANDLE    MiniportAdapterContext ,
    NDIS_HANDLE    WrapperConfigurationContext
);

static NDIS_STATUS
S2EHook_ndis_ResetHandler(
    W_RESET_HANDLER Original,
    PBOOLEAN        AddressingReset,
    NDIS_HANDLE     MiniportAdapterContext
);
static NDIS_STATUS
S2EHook_ndis_SendHandler(
    W_SEND_HANDLER Original,
    NDIS_HANDLE    MiniportAdapterContext,
    PNDIS_PACKET   Packet,
    UINT           Flags
);

static NDIS_STATUS
S2EHook_ndis_SetInformationHandler(
    W_QUERY_INFORMATION_HANDLER Original,
    /* _In_ */  NDIS_HANDLE     MiniportAdapterContext,
    /* _In_ */  NDIS_OID        Oid,
    /* _In_ */  PVOID           InformationBuffer,
    /* _In_ */  ULONG           InformationBufferLength,
    /* _Out_*/  PULONG          BytesWritten,
    /* _Out_*/  PULONG          BytesNeeded
);

static NDIS_STATUS
S2EHook_ndis_TransferDataHandler(
    W_TRANSFER_DATA_HANDLER Original,
    /* _Out_ */ PNDIS_PACKET            Packet,
    /* _Out_ */ PUINT                   BytesTransferred,
    /* _In_  */ NDIS_HANDLE             MiniportAdapterContext,
    /* _In_  */ NDIS_HANDLE             MiniportReceiveContext,
    /* _In_  */ UINT                    ByteOffset,
    /* _In_  */ UINT                    BytesToTransfer
);

static VOID
S2EHook_ndis_ReturnPacketHandler(
    W_RETURN_PACKET_HANDLER Original,
    /* _In_ */  NDIS_HANDLE MiniportAdapterContext,
    /* _In_ */ PNDIS_PACKET Packet
);

static VOID
S2EHook_ndis_SendPacketsHandler(
    W_SEND_PACKETS_HANDLER     Original,
    /* _In_ */ NDIS_HANDLE   MiniportAdapterContext,
    /* _In_ */ PPNDIS_PACKET PacketArray,
    /* _In_ */ UINT          NumberOfPackets
);

static VOID
S2EHook_ndis_AllocateCompleteHandler(
    W_ALLOCATE_COMPLETE_HANDLER        Original,
    /* _In_ */ NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */ PVOID                   VirtualAddress,
    /* _In_ */ PNDIS_PHYSICAL_ADDRESS  PhysicalAddress,
    /* _In_ */ ULONG                   Length,
    /* _In_ */ PVOID                   Context
);

static VOID
S2EHook_ndis_CancelSendPacketsHandler(
    W_CANCEL_SEND_PACKETS_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext,
    PVOID                   CancelId
);


////////////////////////////////////////////////////////////////////////////////////////////////

static VOID S2EHook_ndis_StatusHandler(
    NDIS_M_STATUS_HANDLER   Original,
    NDIS_HANDLE             MiniportHandle,
    NDIS_STATUS             GeneralStatus,
    PVOID                   StatusBuffer,
    UINT                    StatusBufferSize
);

static VOID S2EHook_ndis_SendCompleteHandler(
    NDIS_M_SEND_COMPLETE_HANDLER Original,
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status
);

static VOID S2EHook_ndis_TimerFunction (
     PNDIS_TIMER_FUNCTION    Original,
     PVOID                   SystemSpecific1,
     PVOID                   FunctionContext,
     PVOID                   SystemSpecific2,
     PVOID                   SystemSpecific3
);
////////////////////////////////////////////////////////////////////////////////////////////////


VOID
S2EHook_NdisMRegisterMiniport_RegisterEntryPoints(
    /* IN */ NDIS_HANDLE    NdisWrapperHandle,
    /* IN */ PNDIS_MINIPORT_CHARACTERISTICS    MiniportCharacteristics,
    /* IN */ UINT    CharacteristicsLength)
{
    if (MiniportCharacteristics->MajorNdisVersion > 5) {
        S2EMessageFmt("%s bad version %x\n", __FUNCTION__, MiniportCharacteristics->MajorNdisVersion);
        return;
    }

    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, CheckForHangHandler);     //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, DisableInterruptHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, EnableInterruptHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, HaltHandler);             //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, HandleInterruptHandler);  //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, InitializeHandler);       //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, ISRHandler);              //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, QueryInformationHandler); //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, ReconfigureHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, ResetHandler);            //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, SendHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, SetInformationHandler);   //OK
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, TransferDataHandler);

    //
    // Extensions for NDIS 4.0
    //
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, ReturnPacketHandler);     //TBD
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, SendPacketsHandler);      //OK (with one)
    REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, AllocateCompleteHandler); //TBD

    //
    // Extensions for NDIS 5.0
    //
    if (MiniportCharacteristics->MajorNdisVersion == 5) {
        REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, CoCreateVcHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, CoDeleteVcHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, CoActivateVcHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, CoDeactivateVcHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, CoSendPacketsHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, CoRequestHandler);

        //
        // Extensions for NDIS 5.1
        //
        if (MiniportCharacteristics->MinorNdisVersion == 1) {
            REGISTER_NDIS_ENTRYPOINT_HOOK(NdisWrapperHandle, MiniportCharacteristics, CancelSendPacketsHandler); //OK
            REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, PnPEventNotifyHandler); //TBD
            REGISTER_NDIS_ENTRYPOINT(NdisWrapperHandle, MiniportCharacteristics, AdapterShutdownHandler); //TBD
        }
    }
}

VOID S2EHook_NdisMRegisterUnloadHandler_RegisterEntryPoints(
    /* _In_ */  NDIS_HANDLE    NdisWrapperHandle,
    /* _In_ */  PDRIVER_UNLOAD UnloadHandler
    )
{
    S2ERegisterDriverEntryPoint((UINT64) NdisWrapperHandle, "MiniportUnloadHandler", UnloadHandler, NULL);
}

VOID S2EHook_NdisMInitializeTimer_RegisterEntryPoint(
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_TIMER_FUNCTION TimerFunction
    )
{
    S2ERegisterDriverEntryPoint((UINT64) MiniportAdapterHandle, "NdisMInitializeTimer", TimerFunction, S2EHook_ndis_TimerFunction);
}

////////////////////////////////////////////////////////////////////////////////////////////////

static NDIS_STATUS S2EHook_ndis_InitializeHandler(
    W_INITIALIZE_HANDLER Original,
    PNDIS_STATUS            OpenErrorStatus,
    PUINT                   SelectedMediumIndex,
    PNDIS_MEDIUM            MediumArray,
    UINT                    MediumArraySize,
    NDIS_HANDLE             MiniportAdapterContext,
    NDIS_HANDLE             WrapperConfigurationContext)
{
    NDIS_STATUS Result;
    NDIS_MINIPORT_BLOCK *Block = (NDIS_MINIPORT_BLOCK *) MiniportAdapterContext;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);

    //Registering internal APIs
    REGISTER_NDIS_LIBRARY_HOOK(Original, MiniportAdapterContext, Block, StatusHandler);
    REGISTER_NDIS_LIBRARY_HOOK(Original, MiniportAdapterContext, Block, SendCompleteHandler);

    SymbHwActivateSymbolicPciBus(TRUE);

    Result = Original(OpenErrorStatus, SelectedMediumIndex,
             MediumArray, MediumArraySize, MiniportAdapterContext,
             WrapperConfigurationContext);

    S2EPrintExpression(Result, "Result");
    S2EPrintExpression(*OpenErrorStatus, "OpenErrorStatus");

    if (Result != NDIS_STATUS_SUCCESS) {
        S2EResourceTrackerReportLeaks((UINT64) Original);

        if (S2EGetPathCount() > 1) {
            S2EKillState(*OpenErrorStatus, "ENTRY POINT InitializeHandler failed");
        } else {
            BOOLEAN NewKey;
            S2EMessage("ENTRY POINT InitializeHandler failed while in last state");
            //S2EKVSSetValue("all_failed", 1, &NewKey);
            SymbhwNotifyTestScriptToLoadNextConfig();
            SymbHwActivateSymbolicPciBus(FALSE);
        }
    }

    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    S2ESearcherPopContext();
    return Result;
}

static BOOLEAN
S2EHook_ndis_CheckForHangHandler(
    W_CHECK_FOR_HANG_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
)
{
    BOOLEAN NewKey = TRUE, AlreadyCalled = FALSE;
    BOOLEAN Result;
    CHAR Key[512];
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);

    /* Allow only one call per OID */
    RtlStringCbPrintfA(Key, sizeof(Key), "%s", __FUNCTION__);

    S2EKVSSetValue(Key, 1, &NewKey);
    AlreadyCalled = !NewKey;

    if (AlreadyCalled) {
        S2EMessageFmt("%s was already called, skipping\n", __FUNCTION__);
        return FALSE;
    }

    S2ESearcherPushContext(__FUNCTION__);

    Result = Original(MiniportAdapterContext);

    S2EMessageFmt("ENTRY POINT RETURNED: %s (Unresponsive=%d)\n", __FUNCTION__, Result);
    S2ESearcherPopContext();
    return Result;
}

static VOID
S2EHook_ndis_DisableInterruptHandler(
    W_DISABLE_INTERRUPT_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_EnableInterruptHandler(
    W_ENABLE_INTERRUPT_HANDLER Original,
    NDIS_HANDLE MiniportAdapterContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_HaltHandler(
    W_HALT_HANDLER Original,
    NDIS_HANDLE    MiniportAdapterContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_HandleInterruptHandler(
    W_HANDLE_INTERRUPT_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_ISRHandler(
    W_ISR_HANDLER Original,
    PBOOLEAN      InterruptRecognized,
    PBOOLEAN      QueueMiniportHandleInterrupt,
    NDIS_HANDLE   MiniportAdapterContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    InjectSymbolicInterrupt(0);
    Original(InterruptRecognized, QueueMiniportHandleInterrupt, MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

//TBD: Inject symbolic stuff
static NDIS_STATUS
S2EHook_ndis_QueryInformationHandler(
    W_QUERY_INFORMATION_HANDLER Original,
    /* _In_ */  NDIS_HANDLE     MiniportAdapterContext,
    /* _In_ */  NDIS_OID        Oid,
    /* _In_ */  PVOID           InformationBuffer,
    /* _In_ */  ULONG           InformationBufferLength,
    /* _Out_*/  PULONG          BytesWritten,
    /* _Out_*/  PULONG          BytesNeeded
    )
{
    NDIS_STATUS Status;
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    S2EPrintExpression(Oid, "OID");
    S2EMessageFmt("BufferLength: %#x\n", InformationBufferLength);

    Status = Original(MiniportAdapterContext, Oid,
                      InformationBuffer, InformationBufferLength,
                      BytesWritten, BytesNeeded);

    S2EPrintExpression(Status, __FUNCTION__);
    if (Status == NDIS_STATUS_SUCCESS) {
        if (Oid == OID_GEN_MEDIA_CONNECT_STATUS) {
            NDIS_MEDIA_STATE *State = (NDIS_MEDIA_STATE*) InformationBuffer;
            if (*State == NdisMediaStateDisconnected) {
                //XXX: Depreioritize instead?
                S2EKillState(0, "Killing because network cable is disconnected\n");
            }
        }
    }

    if (!NT_SUCCESS(Status)) {
        S2EMessageFmt("ENTRY POINT %s FAILED\n", __FUNCTION__);
        S2EPrintExpression(Status, "Status");
    }

    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    return Status;
}

static NDIS_STATUS
S2EHook_ndis_ReconfigureHandler(
    W_RECONFIGURE_HANDLER Original,
    PNDIS_STATUS    OpenErrorStatus,
    NDIS_HANDLE    MiniportAdapterContext ,
    NDIS_HANDLE    WrapperConfigurationContext
    )
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(OpenErrorStatus, MiniportAdapterContext, WrapperConfigurationContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static NDIS_STATUS
S2EHook_ndis_ResetHandler(
    W_RESET_HANDLER Original,
    PBOOLEAN        AddressingReset,
    NDIS_HANDLE     MiniportAdapterContext
    )
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(AddressingReset, MiniportAdapterContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static NDIS_STATUS
S2EHook_ndis_SendHandler(
    W_SEND_HANDLER Original,
    NDIS_HANDLE    MiniportAdapterContext,
    PNDIS_PACKET   Packet,
    UINT           Flags
    )
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAdapterContext, Packet, Flags);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

//TBD: Inject symbolic stuff
static NDIS_STATUS
S2EHook_ndis_SetInformationHandler(
    W_SET_INFORMATION_HANDLER Original,
    /* _In_ */  NDIS_HANDLE     MiniportAdapterContext,
    /* _In_ */  NDIS_OID        Oid,
    /* _In_ */  PVOID           InformationBuffer,
    /* _In_ */  ULONG           InformationBufferLength,
    /* _Out_*/  PULONG          BytesWritten,
    /* _Out_*/  PULONG          BytesNeeded
    )
{
    NDIS_STATUS Status;
    CHAR Key[512];
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2EMessageFmt("OID: %#x BufferLength: %#x\n", Oid, InformationBufferLength);

    if (!S2EIsSymbolic(&Oid, sizeof(Oid))) {
        BOOLEAN NewKey = TRUE, AlreadyCalled = FALSE;

        /* Allow only one call per concrete OID */
        RtlStringCbPrintfA(Key, sizeof(Key), "%s_oid_%x", __FUNCTION__, (UINT64) Oid);

        S2EKVSSetValue(Key, 1, &NewKey);
        AlreadyCalled = !NewKey;

        if (AlreadyCalled) {
            S2EMessageFmt("%s was already called, skipping\n", __FUNCTION__);
            return NDIS_STATUS_SUCCESS;
        }
    }

    S2ESearcherPushContext(__FUNCTION__);
    Status = Original(MiniportAdapterContext, Oid,
                      InformationBuffer, InformationBufferLength,
                      BytesWritten, BytesNeeded);

    if (!NT_SUCCESS(Status)) {
        S2EMessageFmt("ENTRY POINT %s FAILED\n", __FUNCTION__);
        S2EPrintExpression(Status, __FUNCTION__);
    }

    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    return Status;
}

static NDIS_STATUS
S2EHook_ndis_TransferDataHandler(
    W_TRANSFER_DATA_HANDLER Original,
    /* _Out_ */ PNDIS_PACKET            Packet,
    /* _Out_ */ PUINT                   BytesTransferred,
    /* _In_  */ NDIS_HANDLE             MiniportAdapterContext,
    /* _In_  */ NDIS_HANDLE             MiniportReceiveContext,
    /* _In_  */ UINT                    ByteOffset,
    /* _In_  */ UINT                    BytesToTransfer
    )
{
    NDIS_STATUS Result;
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(Packet, BytesTransferred, MiniportAdapterContext, MiniportReceiveContext, ByteOffset, BytesToTransfer);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static VOID
S2EHook_ndis_ReturnPacketHandler(
    W_RETURN_PACKET_HANDLER Original,
    /* _In_ */  NDIS_HANDLE MiniportAdapterContext,
    /* _In_ */ PNDIS_PACKET Packet
    )
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, Packet);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_SendPacketsHandler(
    W_SEND_PACKETS_HANDLER     Original,
    /* _In_ */ NDIS_HANDLE   MiniportAdapterContext,
    /* _In_ */ PPNDIS_PACKET PacketArray,
    /* _In_ */ UINT          NumberOfPackets
    )
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, PacketArray, NumberOfPackets);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_AllocateCompleteHandler(
    W_ALLOCATE_COMPLETE_HANDLER        Original,
    /* _In_ */ NDIS_HANDLE             MiniportAdapterContext,
    /* _In_ */ PVOID                   VirtualAddress,
    /* _In_ */ PNDIS_PHYSICAL_ADDRESS  PhysicalAddress,
    /* _In_ */ ULONG                   Length,
    /* _In_ */ PVOID                   Context
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, VirtualAddress, PhysicalAddress, Length, Context);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID
S2EHook_ndis_CancelSendPacketsHandler(
    W_CANCEL_SEND_PACKETS_HANDLER Original,
    NDIS_HANDLE             MiniportAdapterContext,
    PVOID                   CancelId
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAdapterContext, CancelId);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

////////////////////////////////////////////////////////////////////////////////////////////////
static VOID S2EHook_ndis_TimerFunction (
     PNDIS_TIMER_FUNCTION    Original,
     PVOID                   SystemSpecific1,
     PVOID                   FunctionContext,
     PVOID                   SystemSpecific2,
     PVOID                   SystemSpecific3
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s %p\n", __FUNCTION__, Original);
    S2ESearcherPushContext(__FUNCTION__);
    Original(SystemSpecific1, FunctionContext, SystemSpecific2, SystemSpecific3);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s %p\n", __FUNCTION__, Original);
}

////////////////////////////////////////////////////////////////////////////////////////////////
//Called by the driver to indicate the status of the link
static VOID S2EHook_ndis_StatusHandler(
    NDIS_M_STATUS_HANDLER   Original,
    NDIS_HANDLE             MiniportHandle,
    NDIS_STATUS             GeneralStatus,
    PVOID                   StatusBuffer,
    UINT                    StatusBufferSize
    )
{
    S2EMessageFmt("EXTFUNC CALLED: %s %p\n", __FUNCTION__, Original);
    S2EPrintExpression(GeneralStatus, __FUNCTION__);

    if (GeneralStatus == NDIS_STATUS_MEDIA_DISCONNECT) {
        S2EKillState(0, "Killing: driver reported network cable is disconnected\n");
    }

    Original(MiniportHandle, GeneralStatus, StatusBuffer, StatusBufferSize);

    S2EMessageFmt("EXTFUNC RETURNED: %s %p\n", __FUNCTION__, Original);
}

static VOID S2EHook_ndis_SendCompleteHandler(
    NDIS_M_SEND_COMPLETE_HANDLER Original,
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status
)
{
    S2EPrintExpression(Status, __FUNCTION__);
    Original(MiniportAdapterHandle, Packet, Status);
}