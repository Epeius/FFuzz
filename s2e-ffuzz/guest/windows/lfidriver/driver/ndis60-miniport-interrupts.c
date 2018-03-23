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

static BOOLEAN S2EHook_ndis_InterruptHandler(
    MINIPORT_ISR Original,
    /* _In_ */   NDIS_HANDLE             MiniportInterruptContext,
    /* _Out_*/ PBOOLEAN                QueueDefaultInterruptDpc,
    /* _Out_*/ PULONG                  TargetProcessors
);

static VOID S2EHook_ndis_InterruptDpcHandler(
    MINIPORT_INTERRUPT_DPC Original,
    /* _In_ */  NDIS_HANDLE       MiniportInterruptContext,
    /* _In_ */  PVOID             MiniportDpcContext,
    /* _In_ */  PVOID             ReceiveThrottleParameters,
    /* _In_ */  PVOID             NdisReserved2
);

static VOID S2EHook_ndis_DisableInterruptHandler(
    MINIPORT_DISABLE_INTERRUPT Original,
    /* _In_ */  NDIS_HANDLE             MiniportInterruptContext
);

static VOID S2EHook_ndis_EnableInterruptHandler(
    MINIPORT_ENABLE_INTERRUPT Original,
    /* _In_ */  NDIS_HANDLE         MiniportInterruptContext
);


static BOOLEAN S2EHook_ndis_MessageInterruptHandler(
    MINIPORT_MSI_ISR_HANDLER Original,
    /* _In_ */   NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */   ULONG                   MessageId,
    /* _Out_*/ PBOOLEAN                QueueDefaultInterruptDpc,
    /* _Out_*/ PULONG                  TargetProcessors
);

static VOID S2EHook_ndis_MessageInterruptDpcHandler(
    MINIPORT_MSI_INTERRUPT_DPC_HANDLER Original,
    /* _In_ */ NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */ ULONG                   MessageId,
    /* _In_ */ PVOID                   MiniportDpcContext,
#if NDIS_SUPPORT_NDIS620
    /* _In_ */ PVOID                   ReceiveThrottleParameters,
    /* _In_ */ PVOID                   NdisReserved2
#else
    /* _In_ */ PULONG                  NdisReserved1,
    /* _In_ */ PULONG                  NdisReserved2
#endif
);

static VOID S2EHook_ndis_DisableMessageInterruptHandler(
    MINIPORT_DISABLE_MSI_INTERRUPT_HANDLER Original,
    /* _In_ */  NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */  ULONG                   MessageId
);

static VOID S2EHook_ndis_EnableMessageInterruptHandler(
    MINIPORT_ENABLE_MSI_INTERRUPT_HANDLER Original,
    /* _In_ */  NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */  ULONG                   MessageId
);


/**************************************************************/
/* Interrupt handler annotations */
VOID S2EHook_NdisMRegisterInterruptEx_RegisterEntryPoints(
  /* _In_ */  NDIS_HANDLE MiniportAdapterHandle,
  /* _In_ */  NDIS_HANDLE MiniportInterruptContext,
  /* _In_ */  PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS MiniportInterruptCharacteristics,
  /* _Out_*/  PNDIS_HANDLE NdisInterruptHandle
)
{
    REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, InterruptHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, InterruptDpcHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, DisableInterruptHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, EnableInterruptHandler);

    if (MiniportInterruptCharacteristics->MsiSupported) {
        REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, MessageInterruptHandler);
        REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, MessageInterruptDpcHandler);
        REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, DisableMessageInterruptHandler);
        REGISTER_NDIS_ENTRYPOINT_HOOK(MiniportAdapterHandle, MiniportInterruptCharacteristics, EnableMessageInterruptHandler);
    }
}

/**************************************************************/

static BOOLEAN S2EHook_ndis_InterruptHandler(
    MINIPORT_ISR Original,
    /* _In_ */   NDIS_HANDLE             MiniportInterruptContext,
    /* _Out_*/ PBOOLEAN                QueueDefaultInterruptDpc,
    /* _Out_*/ PULONG                  TargetProcessors
)
{
    BOOLEAN Result;
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    InjectSymbolicInterrupt(0);
    Result = Original(MiniportInterruptContext, QueueDefaultInterruptDpc, TargetProcessors);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    return Result;
}

static VOID S2EHook_ndis_InterruptDpcHandler(
    MINIPORT_INTERRUPT_DPC Original,
    /* _In_ */  NDIS_HANDLE       MiniportInterruptContext,
    /* _In_ */  PVOID             MiniportDpcContext,
    /* _In_ */  PVOID             ReceiveThrottleParameters,
    /* _In_ */  PVOID             NdisReserved2
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportInterruptContext, MiniportDpcContext, ReceiveThrottleParameters, NdisReserved2);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_DisableInterruptHandler(
    MINIPORT_DISABLE_INTERRUPT Original,
    /* _In_ */  NDIS_HANDLE             MiniportInterruptContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportInterruptContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_EnableInterruptHandler(
    MINIPORT_ENABLE_INTERRUPT Original,
    /* _In_ */  NDIS_HANDLE         MiniportInterruptContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportInterruptContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}


static BOOLEAN S2EHook_ndis_MessageInterruptHandler(
    MINIPORT_MSI_ISR_HANDLER Original,
    /* _In_ */   NDIS_HANDLE MiniportInterruptContext,
    /* _In_ */   ULONG       MessageId,
    /* _Out_*/ PBOOLEAN      QueueDefaultInterruptDpc,
    /* _Out_*/ PULONG        TargetProcessors
)
{
    BOOLEAN Result;
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    InjectSymbolicInterrupt(0);
    Result = Original(MiniportInterruptContext, MessageId, QueueDefaultInterruptDpc, TargetProcessors);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
    return Result;
}


static VOID S2EHook_ndis_MessageInterruptDpcHandler(
    MINIPORT_MSI_INTERRUPT_DPC_HANDLER Original,
    /* _In_ */ NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */ ULONG                   MessageId,
    /* _In_ */ PVOID                   MiniportDpcContext,
#if NDIS_SUPPORT_NDIS620
    /* _In_ */ PVOID                   ReceiveThrottleParameters,
    /* _In_ */ PVOID                   NdisReserved2
#else
    /* _In_ */ PULONG                  NdisReserved1,
    /* _In_ */ PULONG                  NdisReserved2
#endif
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportInterruptContext, MessageId, MiniportDpcContext, NdisReserved1, NdisReserved2);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_DisableMessageInterruptHandler(
    MINIPORT_DISABLE_MSI_INTERRUPT_HANDLER Original,
    /* _In_ */  NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */  ULONG                   MessageId
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportInterruptContext, MessageId);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static VOID S2EHook_ndis_EnableMessageInterruptHandler(
    MINIPORT_ENABLE_MSI_INTERRUPT_HANDLER Original,
    /* _In_ */  NDIS_HANDLE             MiniportInterruptContext,
    /* _In_ */  ULONG                   MessageId
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportInterruptContext, MessageId);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}
