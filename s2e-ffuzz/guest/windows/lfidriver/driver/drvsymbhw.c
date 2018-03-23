#include <wdm.h>

#include "s2e.h"
#include "hook.h"
#include "symbhw.h"

static PCI_COMMON_CONFIG s_PciConfiguration;
static BOOLEAN s_PciConfigurationInited = FALSE;

BOOLEAN SymbHwIsPciConfigInited(VOID)
{
    return s_PciConfigurationInited;
}

BOOLEAN SymbHwInitializePciConfig(PCI_COMMON_CONFIG *Config)
{
    if (!SymbHwPciDevPresent()) {
        return FALSE;
    }

    s_PciConfiguration = *Config;
    s_PciConfigurationInited = TRUE;

    S2EMessageFmt("SymbHwInitializePciConfig: VID=%x PID=%x\n", Config->VendorID, Config->DeviceID);

    S2EMakeConcolic(&s_PciConfiguration.DeviceSpecific, sizeof(s_PciConfiguration.DeviceSpecific), "pci_cfg");
    return TRUE;
}

BOOLEAN SymbHwPointsToSymbolic(ULONG Offset, ULONG Size)
{
    if (Offset == 0x34 && Size == 1) {
        return TRUE; //Capability pointer
    }

    if (Offset < 40) {
        return FALSE;
    }

    return TRUE;
}

ULONG SymbHwAccessPciConfig(ULONG Offset, PVOID Buffer, ULONG Length, BOOLEAN IsWrite)
{
    UINT8 *Config = (UINT8*)&s_PciConfiguration;

    if (Offset >= sizeof(s_PciConfiguration)) {
        return 0;
    }

    if (Offset + Length > sizeof(s_PciConfiguration)) {
        Length = sizeof(s_PciConfiguration) - Offset;
    }

    if (IsWrite) {
        memcpy(Config + Offset, Buffer, Length);
    } else {
        memcpy(Buffer, Config + Offset, Length);
    }

    S2EMessageFmt("SymbHwAccessPciConfig: %s %d bytes at offset %d\n",
       IsWrite ? "Wrote":"Read", Length, Offset);

    if (Length == 4) {
        S2EPrintExpression(*(UINT32*)Buffer, "pci_cfg");
    }

    return Length;
}
