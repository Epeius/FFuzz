//All the custom, hand-written annotations
//should be declared here and implemented in
//the corresponding C file.

#ifndef WINXP_NDIS_PROTOCOL_CUSTOM

#define WINXP_NDIS_PROTOCOL_CUSTOM

VOID
S2EHook_NdisRegisterProtocol_RegisterEntryPoints(
    /* OUT */ PNDIS_STATUS    Status,
    /* OUT */ PNDIS_HANDLE    NdisProtocolHandle,
    /* IN */ PNDIS_PROTOCOL_CHARACTERISTICS    ProtocolCharacteristics,
    /* IN */ UINT    CharacteristicsLength
);

VOID S2EHook_NdisDeregisterProtocol_DeregisterEntryPoints(
  /* _Out_ */  PNDIS_STATUS Status,
  /* _In_  */  NDIS_HANDLE NdisProtocolHandle
);

#endif