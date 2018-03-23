#ifndef BASEINSTRUCTIONS_H

#define BASEINSTRUCTIONS_H

#include "s2e.h"

typedef enum S2E_BASEINSTRUCTION_COMMANDS {
    ALLOW_CURRENT_PID,
    GET_HOST_CLOCK_MS
} S2E_BASEINSTRUCTION_COMMANDS;

typedef struct S2E_BASEINSTRUCTION_COMMAND {
    S2E_BASEINSTRUCTION_COMMANDS Command;
    union {
        UINT64 Milliseconds;
    };
} S2E_BASEINSTRUCTION_COMMAND;

static void BaseInstrAllowCurrentPid()
{
    S2E_BASEINSTRUCTION_COMMAND Command;
    Command.Command = ALLOW_CURRENT_PID;
    S2EInvokePlugin("BaseInstructions", &Command, sizeof(Command));
}

static UINT64 BaseInstrGetHostClockMs()
{
    S2E_BASEINSTRUCTION_COMMAND Command;
    Command.Command = GET_HOST_CLOCK_MS;
    Command.Milliseconds = 0;
    S2EInvokePlugin("BaseInstructions", &Command, sizeof(Command));
    return Command.Milliseconds;
}

#endif