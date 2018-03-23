//All the custom, hand-written annotations
//should be declared here and implemented in
//the corresponding C file.

#ifndef WINXP_NDIS_MINIPORT_CUSTOM

#define WINXP_NDIS_MINIPORT_CUSTOM

VOID
S2EHook_NdisMRegisterMiniport_RegisterEntryPoints(
    /* IN */ NDIS_HANDLE    NdisWrapperHandle,
    /* IN */ PNDIS_MINIPORT_CHARACTERISTICS    MiniportCharacteristics,
    /* IN */ UINT    CharacteristicsLength);

VOID S2EHook_NdisMInitializeTimer_RegisterEntryPoint(
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_TIMER_FUNCTION TimerFunction
    );

//NdisMQueryAdapterResources
VOID
S2EHook_NdisMQueryAdapterResources(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    WrapperConfigurationContext,
    /* OUT */ PNDIS_RESOURCE_LIST    ResourceList,
    /* IN */ PUINT    BufferSize
);

VOID S2EHook_NdisMIndicateStatus(
    NDIS_HANDLE             MiniportHandle,
    NDIS_STATUS             GeneralStatus,
    PVOID                   StatusBuffer,
    UINT                    StatusBufferSize
    );

VOID S2EHook_NdisMSendComplete(
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status
);
#endif