//All the custom, hand-written annotations
//should be declared here and implemented in
//the corresponding C file.

#ifndef NDIS60_MINIPORT_CUSTOM

#define NDIS60_MINIPORT_CUSTOM

VOID S2EHook_NdisMRegisterMiniportDriver_RegisterEntryPoints(
  /* _In_     */ PDRIVER_OBJECT DriverObject,
  /* _In_     */ PUNICODE_STRING RegistryPath,
  /* _In_opt_ */ NDIS_HANDLE MiniportDriverContext,
  /* _In_     */ PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
  /* _Out_    */ PNDIS_HANDLE NdisMiniportDriverHandle
);

VOID S2EHook_NdisSetOptionalHandlers_RegisterEntryPoints(
    NDIS_HANDLE NdisHandle,
    PNDIS_DRIVER_OPTIONAL_HANDLERS OptionalHandlers
);

VOID S2EHook_NdisMRegisterInterruptEx_RegisterEntryPoints(
  /* _In_ */  NDIS_HANDLE MiniportAdapterHandle,
  /* _In_ */  NDIS_HANDLE MiniportInterruptContext,
  /* _In_ */  PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS MiniportInterruptCharacteristics,
  /* _Out_*/  PNDIS_HANDLE NdisInterruptHandle
);

#endif