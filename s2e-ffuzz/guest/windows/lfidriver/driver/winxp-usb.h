#ifndef _WINXP_USB_H_

#define _WINXP_USB_H_

#include <usb.h>
#include <usbioctl.h>
#include <ndis.h>

typedef struct _S2E_USB_URB_DATA {
    PIRP Irp;
    PURB Urb;
    PVOID *Data;
    UINT32 *Size;
    UINT32 OriginalSize;
} S2E_USB_URB_DATA;

void LfiUsbHandleIOCTL_INTERNAL_USB_SUBMIT_URB(PIRP Irp, BOOLEAN *RegisterCallBack);

/* Wifi data types */
typedef struct _DOT11_FRAME_HEADER {
    UINT16 FrameControl;
    UINT16 Duration;
    UINT8 Bssid[6];
    UINT8 SourceMac[6];
    UINT8 DestMac[6];
    UINT16 SequenceControl;
} DOT11_FRAME_HEADER;

typedef struct _DOT11_BCN_PRB {
    UINT32          Timestamp[2];
    UINT16          BeaconInterval;
    UINT16          Capability;
} DOT11_BCN_PRB;

typedef struct _DOT11_TAG_HEADER {
    UINT8           TagNumber;
    UINT8           TagLength;
} DOT11_TAG_HEADER;

#define DOT11_TAG_SSID 0

BOOLEAN LfiWifiMakeSymbolic(PVOID Frame, INT Size);

void LfiWifiHandleQueryInfo(
    /* _In_ */  NDIS_OID Oid,
    /* _In_ */  PVOID           InformationBuffer,
    /* _In_ */  ULONG           InformationBufferLength,
    /* _Out_*/  PULONG          BytesWritten,
    /* _Out_*/  PULONG          BytesNeeded
);

#endif
