#define NDIS51

#include <ndis.h>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <hook.h>


#define REGISTER_NDIS_ENTRYPOINT(handle, struc, name) \
    if (struc->name) { \
        S2ERegisterDriverEntryPoint((UINT64) handle, #name, struc->name, NULL);\
    }

VOID
S2EHook_NdisRegisterProtocol_RegisterEntryPoints(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_HANDLE    NdisProtocolHandle,
    /* IN */ PNDIS_PROTOCOL_CHARACTERISTICS    ProtocolCharacteristics,
    /* IN */ UINT    CharacteristicsLength
)
{
    if (ProtocolCharacteristics->MajorNdisVersion > 5) {
        return;
    }

    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, OpenAdapterCompleteHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, CloseAdapterCompleteHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, SendCompleteHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, TransferDataCompleteHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, ResetCompleteHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, ReceiveHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, ReceiveCompleteHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, StatusHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, StatusCompleteHandler);

    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, ReceivePacketHandler);

    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, BindAdapterHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, UnbindAdapterHandler);
    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, PnPEventHandler);

    REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, UnloadHandler);


    //
    // Extensions for NDIS 5.0
    //
    if (ProtocolCharacteristics->MajorNdisVersion == 5) {
        REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, CoSendCompleteHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, CoStatusHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, CoReceivePacketHandler);
        REGISTER_NDIS_ENTRYPOINT(NdisProtocolHandle, ProtocolCharacteristics, CoAfRegisterNotifyHandler);
    }
}


VOID S2EHook_NdisDeregisterProtocol_DeregisterEntryPoints(
  /* _Out_ */  PNDIS_STATUS Status,
  /* _In_  */  NDIS_HANDLE NdisProtocolHandle
)
{
    S2EDeregisterDriverEntryPoint((UINT_PTR) NdisProtocolHandle, NULL);
}
