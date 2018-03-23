#ifndef _S2E_SYMBHW_H_

#define _S2E_SYMBHW_H_

#include "s2e.h"
#include "keyvalue.h"

#pragma warning(disable:4201) //nonstandard extension used : nameless struct/union

/********************************************************/
/* SymbolicHardware */
__declspec(align(8))
typedef enum _S2E_SYMBHW_COMMANDS {
    SYMBHW_PLUG_IN,
    SYMBHW_HAS_PCI,
    SYMBHW_UNPLUG,
    SYMBHW_REGISTER_DMA_MEMORY,
    SYMBHW_UNREGISTER_DMA_MEMORY,
    SYMBHW_INJECT_INTERRUPT,
    SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS,
    SYMBHW_QUERY_RESOURCE_SIZE,
    SYMBHW_SELECT_NEXT_PCI_CONFIG,
    SYMBHW_DEACTIVATE_SYMBOLIC_PCI_BUS,
    SYMBHW_GET_CURRENT_PCI_CONFIG,
} S2E_SYMBHW_COMMANDS;

__declspec(align(8))
typedef struct _S2E_SYMHW_DMA_MEMORY {
    UINT64 PhysicalAddress;
    UINT64 Size;
} S2E_SYMHW_DMA_MEMORY;

__declspec(align(8))
typedef struct _S2E_SYMHW_RESOURCE {
    /* Input to identify the resource */
    UINT64 PhysicalAddress;

    /* Output is a constrained symbolic size */
    UINT64 Size;
} S2E_SYMHW_RESOURCE;

__declspec(align(8))
typedef struct _S2E_SYMBHW_COMMAND {
    S2E_SYMBHW_COMMANDS Command;
    union {
        S2E_SYMHW_DMA_MEMORY Memory;
        S2E_SYMHW_RESOURCE Resource;
        UINT64 HasPci;
        UINT64 InterruptLevel;
        UINT64 SelectNextConfigSuccess;
        UINT64 DeviceIndex;
        UINT64 CurrentConfig;
    };
} S2E_SYMBHW_COMMAND;

static VOID S2ERegisterDmaRegion(UINT64 PhysicalAddress, UINT64 Size)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_REGISTER_DMA_MEMORY;
    Command.Memory.PhysicalAddress = PhysicalAddress;
    Command.Memory.Size = Size;

    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
}

static VOID S2EFreeDmaRegion(UINT64 PhysicalAddress, UINT64 Size)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_UNREGISTER_DMA_MEMORY;
    Command.Memory.PhysicalAddress = PhysicalAddress;
    Command.Memory.Size = Size;

    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
}

static BOOLEAN SymbHwPciDevPresent(VOID)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_HAS_PCI;
    Command.HasPci = 0;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
    return (BOOLEAN) Command.HasPci;
}

static VOID InjectSymbolicInterrupt(UINT64 Level)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_INJECT_INTERRUPT;
    Command.InterruptLevel = Level;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
}

static void SymbHwActivateSymbolicPciBus(BOOLEAN Active)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = Active ? SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS : SYMBHW_DEACTIVATE_SYMBOLIC_PCI_BUS;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
}

static BOOLEAN SymbHwQueryResourceSize(UINT64 PhysicalAddress, UINT64 *Size)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_QUERY_RESOURCE_SIZE;
    Command.Resource.PhysicalAddress = PhysicalAddress;
    Command.Resource.Size = 0;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
    *Size = Command.Resource.Size;
    return (*Size) != 0;
}

static VOID SymbhwHotPlug(BOOLEAN PlugIn)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = PlugIn ? SYMBHW_PLUG_IN : SYMBHW_UNPLUG;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
}

static BOOLEAN SymbhwSelectNextConfig()
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_SELECT_NEXT_PCI_CONFIG;
    Command.SelectNextConfigSuccess = 0;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
    return (BOOLEAN) Command.SelectNextConfigSuccess;
}

static UINT64 SymbhwGetCurrentPciConfig(UINT64 DeviceIndex)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_GET_CURRENT_PCI_CONFIG;
    Command.DeviceIndex = DeviceIndex;
    S2EInvokePlugin("SymbolicHardware", &Command, sizeof(Command));
    return Command.CurrentConfig;
}

static BOOLEAN SymbhwSelectNextConfigAndNotify()
{
    //TODO: more than 1 pci device
    UINT64 CurrentConfig = SymbhwGetCurrentPciConfig(0);
    CHAR String[512];
    BOOLEAN NewKey = TRUE;
    CONST CHAR *Fmt = "pci_symbhw_config_%d";

    #if defined(USER_APP)
    sprintf_s(String, sizeof(String)-1, Fmt, CurrentConfig + 1);
    #else
    RtlStringCbPrintfA(String, sizeof(String) - 1, Fmt, CurrentConfig + 1);
    #endif
    S2EMessageFmt("SymbhwSelectNextConfigAndNotify: checking %s\n", String);

    S2EKVSSetValue(String, 1, &NewKey);
    if (!NewKey) {
        //A path has already tried this hardware config
        return FALSE;
    }

    return SymbhwSelectNextConfig();
}

static VOID SymbhwNotifyTestScriptOfFailure()
{
    BOOLEAN NewKey;
    S2EKVSSetValue("all_failed", 1, &NewKey);
}

static VOID SymbhwNotifyTestScriptToLoadNextConfig()
{
    BOOLEAN NewKey;
    S2EKVSSetValueEx("load_next_config", 1, &NewKey, TRUE);
}

#endif