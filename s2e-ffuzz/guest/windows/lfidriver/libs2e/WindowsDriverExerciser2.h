#ifndef S2E_WINDOWSDRIVEREXERCISER2

#define S2E_WINDOWSDRIVEREXERCISER2

#include "s2e.h"

typedef struct _S2E_WINEX2_DECIDE_INJECT_FAULT {
    /* The guest driver populates these */
    UINT64 LibraryFunction;
    UINT64 LibraryFunctionName;
    UINT64 LibraryName;
    UINT64 CallSite;

    /**
     * The guest passes a pointer to a buffer to the plugin
     * so that it can generate a user-friendly call site identification
     * (module name + relative address).
     */
    UINT64 CallSiteModuleRelative;
    UINT64 CallSiteIdStr;
    UINT32 CallSiteIdStrSize;

    UINT32 Outcome;
} S2E_WINEX2_DECIDE_INJECT_FAULT;

typedef enum _S2E_WINEX2_PLUGIN_COMMANDS {
    DECIDE_INJECT_FAULT,
    GET_FAULT_COUNT, INCREMENT_FAULT_COUNT
}S2E_WINEX2_PLUGIN_COMMANDS;

typedef struct _S2E_WINEX2_PLUGIN_COMMAND {
    S2E_WINEX2_PLUGIN_COMMANDS Command;
    union {
        S2E_WINEX2_DECIDE_INJECT_FAULT InjectFault;
        UINT64 FaultCount;
    };
}S2E_WINEX2_PLUGIN_COMMAND;


static INT DecideInjectFault(UINT_PTR LibraryFunction, PCSTR LibraryFunctionName,
                      PCSTR LibraryName, UINT_PTR CallSite,
                      PSTR CallSiteIdStr, UINT32 CallSiteIdStrSize)
{
    S2E_WINEX2_PLUGIN_COMMAND Command;
    Command.Command = DECIDE_INJECT_FAULT;
    Command.InjectFault.CallSite = CallSite;
    Command.InjectFault.LibraryFunction = LibraryFunction;
    Command.InjectFault.LibraryFunctionName = (UINT_PTR) LibraryFunctionName;
    Command.InjectFault.LibraryName = (UINT_PTR) LibraryName;
    Command.InjectFault.CallSiteIdStr = (UINT_PTR) CallSiteIdStr;
    Command.InjectFault.CallSiteIdStrSize = CallSiteIdStrSize;
    Command.InjectFault.Outcome = 0;

    __s2e_touch_string(LibraryFunctionName);
    __s2e_touch_string(LibraryName);
    S2EInvokePlugin("WindowsDriverExerciser2", &Command, sizeof(Command));

    return Command.InjectFault.Outcome;
}

static UINT64 S2EGetInjectedFaultCount(VOID)
{
    S2E_WINEX2_PLUGIN_COMMAND Command;
    Command.Command = GET_FAULT_COUNT;
    Command.FaultCount = 0;
    S2EInvokePlugin("WindowsDriverExerciser2", &Command, sizeof(Command));
    return Command.FaultCount;
}

static VOID S2EIncrementFaultCount(VOID)
{
    S2E_WINEX2_PLUGIN_COMMAND Command;
    Command.Command = INCREMENT_FAULT_COUNT;
    S2EInvokePlugin("WindowsDriverExerciser2", &Command, sizeof(Command));
}

/**
 * Kills the current state only if it won't prevent future
 * progress of the path exploration.
 */
static VOID S2EDriverExerciserKillState(UINT32 Status, PCSTR Message)
{
    UINT64 FaultCount = S2EGetInjectedFaultCount();
    if (FaultCount != 0) {
        S2EMessageFmt("WindowsDriverExerciser2: faultcount=%d\n", FaultCount);
        S2EKillState(Status, Message);
    }
}

#endif
