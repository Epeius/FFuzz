#include <s2e.h>
#include <keyvalue.h>
#include "winxp-usb.h"

BOOLEAN LfiWifiMakeSymbolic(PVOID _Frame, INT Size)
{
    static BOOLEAN Done = FALSE;

    if (!Done) {
        UINT8 *Frame = (UINT8*) _Frame;
        DOT11_FRAME_HEADER *Header = (DOT11_FRAME_HEADER*) Frame;
        Frame += sizeof(*Header);
        Size -= sizeof(*Header);

        if (Header->FrameControl == 0x80) {
            DOT11_BCN_PRB *Prb = (DOT11_BCN_PRB*) (Frame);
            Frame += sizeof(*Prb);
            Size -= sizeof(*Prb);

            while (Size > 0) {
                DOT11_TAG_HEADER *TagHeader = (DOT11_TAG_HEADER*) (Frame);
                UINT8 *TagData = (UINT8*) &TagHeader[1];

                INT Sz = sizeof(*TagHeader) + TagHeader->TagLength;
                Frame += Sz;
                Size -= Sz;

                S2EMessageFmt("802.11 Beacon Tag %x Length=%x RemSize=%d\n", TagHeader->TagNumber, TagHeader->TagLength, Size);
                if (TagHeader->TagNumber == DOT11_TAG_SSID) {
                    UINT8 OriginalLength = TagHeader->TagLength;
                    CHAR SSID[257];

                    strncpy(SSID, TagData, TagHeader->TagLength);
                    SSID[TagHeader->TagLength] = 0;
                    S2EMessageFmt("   SSID %s\n", SSID);

                    //S2EMakeConcolic(&TagHeader->TagLength, sizeof(TagHeader->TagLength), "SSIDLength");
                    /*if (TagHeader->TagLength > OriginalLength) {
                        S2EKillState(0, "OriginalLength too big");
                    }*/
                } else {
                    if (TagHeader->TagNumber == 0xdd) {
                        S2EMakeConcolic(TagData, TagHeader->TagLength, "Tag");
                    }
                }
            }

            //S2EMakeConcolic(&Header->FrameControl, sizeof(Header->FrameControl), "FrameControl");
            S2EMakeConcolic(&Prb->Capability, sizeof(Prb->Capability), "Capability");
            //S2EMakeConcolic(Frame, Size, "Frame");
            Done = TRUE;
        }
    }
    return Done;
}

void LfiWifiHandleQueryInfo(
    /* _In_ */  NDIS_OID Oid,
    /* _In_ */  PVOID           InformationBuffer,
    /* _In_ */  ULONG           InformationBufferLength,
    /* _Out_*/  PULONG          BytesWritten,
    /* _Out_*/  PULONG          BytesNeeded
)
{
    switch(Oid) {
        case OID_802_11_BSSID_LIST: {
            ULONG i;
            NDIS_802_11_BSSID_LIST_EX *Result = InformationBuffer;
            S2EMessageFmt("OID_802_11_BSSID_LIST BytesWritten=%d BytesNeeded=%d items=%d\n",
                *BytesWritten, *BytesNeeded, Result->NumberOfItems);

            S2EHexDump("InformationBuffer", InformationBuffer, *BytesWritten);

            if (Result->NumberOfItems > 0) {
                S2EKillState(0, "Found SSIDs");
            }
        } break;

        default:  {

        } break;
    }
}

void LfiUsbHandleIOCTL_INTERNAL_USB_SUBMIT_URB(PIRP Irp, BOOLEAN *RegisterCallBack)
{
    PIO_STACK_LOCATION Stack;
    PURB Urb;

    Stack = IoGetNextIrpStackLocation(Irp);
    Urb = (PURB) Stack->Parameters.Others.Argument1;

    S2EMessageFmt("      IOCTL_INTERNAL_USB_SUBMIT_URB: URB=%p Length=%d Function=%#x UsbdFlags=%#x\n",
                    Urb, Urb->UrbHeader.Length, Urb->UrbHeader.Function, Urb->UrbHeader.UsbdFlags);

    switch (Urb->UrbHeader.Function) {
        case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER: {
            S2EMessageFmt("       URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER "
                "PipeHandle=%p TransferFlags=%#x TransferBufferLength=%#x TransferBuffer=%p TransferBufferMDL=%p\n",
                Urb->UrbBulkOrInterruptTransfer.PipeHandle,
                Urb->UrbBulkOrInterruptTransfer.TransferFlags,
                Urb->UrbBulkOrInterruptTransfer.TransferBufferLength,
                Urb->UrbBulkOrInterruptTransfer.TransferBuffer,
                Urb->UrbBulkOrInterruptTransfer.TransferBufferMDL);

            if (Urb->UrbBulkOrInterruptTransfer.TransferFlags & USBD_TRANSFER_DIRECTION_IN) {
                S2E_USB_URB_DATA *Range;
                S2EMessageFmt("         USBD_TRANSFER_DIRECTION_IN\n");
                Range = ExAllocatePoolWithTag(NonPagedPool, sizeof(S2E_USB_URB_DATA), 0x123445);
                if (Range) {
                    Range->Irp = Irp;
                    Range->Urb = Urb;
                    Range->Data = &Urb->UrbBulkOrInterruptTransfer.TransferBuffer;
                    Range->Size = &Urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
                    Range->OriginalSize = Urb->UrbBulkOrInterruptTransfer.TransferBufferLength;
                    S2EKVSSetValueIntKeyEx((UINT_PTR) Irp, (UINT_PTR) Range, NULL, TRUE);
                    *RegisterCallBack = TRUE;
                }
            } else {
                S2EMessageFmt("         USBD_TRANSFER_DIRECTION_OUT\n");
                S2EHexDump("USB Buffer", Urb->UrbBulkOrInterruptTransfer.TransferBuffer,
                    Urb->UrbBulkOrInterruptTransfer.TransferBufferLength);
            }
        } break;
    }
}
