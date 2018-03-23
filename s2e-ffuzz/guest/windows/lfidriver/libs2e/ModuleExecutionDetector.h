#ifndef S2E_MODULE_EXECUTION_DETECTOR

#define S2E_MODULE_EXECUTION_DETECTOR

#include "s2e.h"

/********************************************************/
/* ModuleExecutionDetector */

__declspec(align(8))
typedef struct _S2E_MODEX_MODULE {
    /**
     * IN: absolute address which we want
     * to convert to a module name and a relative address.
     */
    UINT64 AbsoluteAddress;

    /* IN: number of bytes in ModuleName */
    UINT64 ModuleNameSize;

    /* OPTIONAL IN/OUT: pointer to to the module name in guest space */
    UINT64 ModuleName;

    /* OUT: the computed address relative to the module's native base */
    UINT64 NativeBaseAddress;
} S2E_MODEX_MODULE;

__declspec(align(8))
typedef enum _S2E_MODEX_DETECTOR_COMMANDS {
    GET_MODULE
} S2E_MODEX_DETECTOR_COMMANDS;

__declspec(align(8))
typedef struct _S2E_MODEX_DETECTOR_COMMAND {
    S2E_MODEX_DETECTOR_COMMANDS Command;
    union {
        S2E_MODEX_MODULE Module;
    };
} S2E_MODEX_DETECTOR_COMMAND;

static BOOLEAN S2EGetModuleInfo(UINT64 Address, PSTR ModuleName, INT ModuleNameSize, UINT64 *NativeAddress)
{
    S2E_MODEX_DETECTOR_COMMAND Command;
    Command.Command = GET_MODULE;
    Command.Module.AbsoluteAddress = Address;
    Command.Module.ModuleName = (UINT_PTR) ModuleName;
    Command.Module.ModuleNameSize = ModuleNameSize;
    Command.Module.NativeBaseAddress = 0;

    __s2e_touch_buffer(ModuleName, ModuleNameSize);
    S2EInvokePlugin("ModuleExecutionDetector", &Command, sizeof(Command));

    if (NativeAddress) {
        *NativeAddress = Command.Module.NativeBaseAddress;
    }

    return Command.Module.NativeBaseAddress != 0;
}

static BOOLEAN S2EGetModuleInfoStr(UINT64 Address, PSTR Info, INT InfoSize)
{
    CHAR ModuleName[64] = {0};
    UINT64 NativeAddress;

    BOOLEAN Ret = S2EGetModuleInfo(Address, ModuleName, sizeof(ModuleName), &NativeAddress);
    if (!Ret) {
        return FALSE;
    }

    RtlStringCbPrintfA(Info, InfoSize, "%s!%#x", ModuleName, NativeAddress);
    return TRUE;
}

#endif
