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

/**************************************************************/
static NDIS_STATUS S2EHook_ndis_MiniportAddDeviceHandler (
    MINIPORT_ADD_DEVICE Original,
    /* _In_ */ NDIS_HANDLE              NdisMiniportHandle,
    /* _In_ */ NDIS_HANDLE              MiniportDriverContext
);

static VOID S2EHook_ndis_MiniportRemoveDeviceHandler (
    MINIPORT_REMOVE_DEVICE_HANDLER Original,
    /* _In_ */ NDIS_HANDLE              MiniportAddDeviceContext
);

static NDIS_STATUS S2EHook_ndis_MiniportFilterResourceRequirementsHandler (
    MINIPORT_FILTER_RESOURCE_REQUIREMENTS_HANDLER Original,
    /* _In_ */ NDIS_HANDLE              MiniportAddDeviceContext,
    /* _In_ */ PIRP                     Irp
);

static NDIS_STATUS S2EHook_ndis_MiniportStartDeviceHandler (
    MINIPORT_START_DEVICE_HANDLER Original,
    /* _In_ */ NDIS_HANDLE              MiniportAddDeviceContext,
    /* _In_ */ PIRP                     Irp
);

static VOID RegisterPnpCharacteristics(
    NDIS_HANDLE Handle,
    PNDIS_MINIPORT_PNP_CHARACTERISTICS Characteristics)
{
    REGISTER_NDIS_ENTRYPOINT_HOOK(Handle, Characteristics, MiniportAddDeviceHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(Handle, Characteristics, MiniportRemoveDeviceHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(Handle, Characteristics, MiniportFilterResourceRequirementsHandler);
    REGISTER_NDIS_ENTRYPOINT_HOOK(Handle, Characteristics, MiniportStartDeviceHandler);
}
/**************************************************************/

VOID S2EHook_NdisSetOptionalHandlers_RegisterEntryPoints(
    NDIS_HANDLE NdisHandle,
    PNDIS_DRIVER_OPTIONAL_HANDLERS OptionalHandlers
)
{
    if (!OptionalHandlers) {
        S2EKillState(0, "NdisSetOptionalHandlers - OptionalHandlers must not be NULL");
        return;
    }

    if (OptionalHandlers->Header.Type == NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS) {
        if (OptionalHandlers->Header.Revision != NDIS_MINIPORT_PNP_CHARACTERISTICS_REVISION_1) {
            S2EKillState(0, "NdisSetOptionalHandlers - Revision must be NDIS_MINIPORT_PNP_CHARACTERISTICS_REVISION_1");
        }
        if (OptionalHandlers->Header.Size != NDIS_SIZEOF_MINIPORT_PNP_CHARACTERISTICS_REVISION_1) {
            S2EMessageFmt("NdisSetOptionalHandlers: header size: %#x (expected %#x)\n",
                OptionalHandlers->Header.Size, NDIS_SIZEOF_MINIPORT_PNP_CHARACTERISTICS_REVISION_1);
            //XXX: Not sure why it fails sometimes
            //S2EKillState(0, "NdisSetOptionalHandlers - Size must be NDIS_SIZEOF_MINIPORT_PNP_CHARACTERISTICS_REVISION_1");
        }

        RegisterPnpCharacteristics(NdisHandle, (PNDIS_MINIPORT_PNP_CHARACTERISTICS) OptionalHandlers);
        return;
    }
}

/**************************************************************/

static NDIS_STATUS S2EHook_ndis_MiniportAddDeviceHandler (
    MINIPORT_ADD_DEVICE Original,
    /* _In_ */ NDIS_HANDLE              NdisMiniportHandle,
    /* _In_ */ NDIS_HANDLE              MiniportDriverContext
)
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(NdisMiniportHandle, MiniportDriverContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static VOID S2EHook_ndis_MiniportRemoveDeviceHandler (
    MINIPORT_REMOVE_DEVICE_HANDLER Original,
    /* _In_ */ NDIS_HANDLE              MiniportAddDeviceContext
)
{
    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Original(MiniportAddDeviceContext);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);
}

static NDIS_STATUS S2EHook_ndis_MiniportFilterResourceRequirementsHandler (
    MINIPORT_FILTER_RESOURCE_REQUIREMENTS_HANDLER Original,
    /* _In_ */ NDIS_HANDLE              MiniportAddDeviceContext,
    /* _In_ */ PIRP                     Irp
)
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAddDeviceContext, Irp);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}

static NDIS_STATUS S2EHook_ndis_MiniportStartDeviceHandler (
    MINIPORT_START_DEVICE_HANDLER Original,
    /* _In_ */ NDIS_HANDLE              MiniportAddDeviceContext,
    /* _In_ */ PIRP                     Irp
)
{
    NDIS_STATUS Result;

    S2EMessageFmt("ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);
    Result = Original(MiniportAddDeviceContext, Irp);
    S2ESearcherPopContext();
    S2EMessageFmt("ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    return Result;
}
