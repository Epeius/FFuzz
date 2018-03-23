#define NDIS_MINIPORT_DRIVER

#define NDIS51_MINIPORT

#include <ndis.h>
#include <ntdef.h>

#include <s2e.h>
#include <symbhw.h>
#include "hook.h"
#include "drvsymbhw.h"

#include "winxp-ndis-miniport-custom.h"

//NdisMQueryAdapterResources
VOID
S2EHook_NdisMQueryAdapterResources(
    /* OUT */ PNDIS_STATUS    Status,
    /* IN */ NDIS_HANDLE    WrapperConfigurationContext,
    /* OUT */ PNDIS_RESOURCE_LIST    ResourceList,
    /* IN */ PUINT    BufferSize
)
{

    BOOLEAN NullSize = *BufferSize == 0;
    NdisMQueryAdapterResources(    Status,    WrapperConfigurationContext,    ResourceList,    BufferSize);
    if (!NT_SUCCESS(*Status) || NullSize) {
        return;
    }

    {
        ULONG i;
        for (i = 0; i < ResourceList->Count; ++i) {
            CM_PARTIAL_RESOURCE_DESCRIPTOR D = ResourceList->PartialDescriptors[i];
            CM_PARTIAL_RESOURCE_DESCRIPTOR *pD = &ResourceList->PartialDescriptors[i];
            UINT64 Size;

            S2EMessageFmt("Resource %d: type=%#x\n", i, D.Type);

            switch(D.Type) {
                case CmResourceTypePort: {
                    S2EMessageFmt("   type=%s Start=%#lx Length=%#lx\n", "CmResourceTypePort",
                                  (UINT_PTR) D.u.Port.Start.QuadPart, (UINT_PTR) D.u.Port.Length);
                    if (SymbHwQueryResourceSize(D.u.Port.Start.QuadPart, &Size)) {
                        S2EPrintExpression((ULONG) Size, "NdisMQueryAdapterResources: port size");
                        pD->u.Port.Length = (ULONG) Size;
                    }
                } break;

                case CmResourceTypeInterrupt: {
                    S2EMessageFmt("   type=%s vector=%#x\n", "CmResourceTypeInterrupt",
                                  D.u.Interrupt.Vector);
                } break;

                case CmResourceTypeMemory: {
                    S2EMessageFmt("   type=%s Start=%#lx Length=%#lx\n", "CmResourceTypeMemory",
                                  (UINT_PTR) D.u.Memory.Start.QuadPart, (UINT_PTR) D.u.Memory.Length);
                    if (SymbHwQueryResourceSize(D.u.Memory.Start.QuadPart, &Size)) {
                        S2EPrintExpression((ULONG) Size, "NdisMQueryAdapterResources: memory size");
                        pD->u.Memory.Length = (ULONG) Size;
                    }
                } break;

                case CmResourceTypeDevicePrivate: {
                    S2EMessageFmt("   type=%s %#x %#x %#x %#x\n", "CmResourceTypeDevicePrivate",
                                  pD->u.DevicePrivate.Data[0],
                                  pD->u.DevicePrivate.Data[1],
                                  pD->u.DevicePrivate.Data[2],
                                  pD->u.DevicePrivate.Data[3]);
                } break;
            }
        }
    }

    return;
}

VOID S2EHook_NdisMIndicateStatus(
    NDIS_HANDLE             MiniportHandle,
    NDIS_STATUS             GeneralStatus,
    PVOID                   StatusBuffer,
    UINT                    StatusBufferSize
    )
{
    //TODO: Ndis 6 uses NdisMIndicateStatusEx
    S2EPrintExpression(GeneralStatus, __FUNCTION__);
    if (GeneralStatus == NDIS_STATUS_MEDIA_DISCONNECT) {
        S2EKillState(0, "Killing: driver reported network cable is disconnected\n");
    } else {
        S2EMessageFmt("%s: network cable connected\n", __FUNCTION__);
    }

    NdisMIndicateStatus(MiniportHandle, GeneralStatus, StatusBuffer, StatusBufferSize);
}

VOID S2EHook_NdisMSendComplete(
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_PACKET Packet,
    NDIS_STATUS Status
)
{
    S2EPrintExpression(Status, __FUNCTION__);
    NdisMSendComplete(MiniportAdapterHandle, Packet, Status);
}