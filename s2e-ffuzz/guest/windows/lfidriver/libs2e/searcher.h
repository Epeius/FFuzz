#ifndef _S2E_SEARCHER_H_

#define _S2E_SEARCHER_H_

#include "s2e.h"
#pragma warning(disable:4201) //nonstandard extension used : nameless struct/union

/********************************************************/
/* DDTSearcher */
__declspec(align(8))
typedef enum _S2E_DDTSEARCHER_COMMANDS {
    SEARCHER_CHANGE_PRIORITY,
    SEARCHER_PUSH_CONTEXT,
    SEARCHER_POP_CONTEXT,
    SEARCHER_SET_PHASE
} S2E_DDTSEARCHER_COMMANDS;

__declspec(align(8))
typedef struct _S2E_DDTSEARCHER_COMMAND {
    S2E_DDTSEARCHER_COMMANDS Command;
    union {
        INT64  RelativePriority;
        UINT64 ContextName;
        UINT64 PhaseNumber;
    };
} S2E_DDTSEARCHER_COMMAND;

static VOID S2ESearcherPushContext(PCSTR Name)
{
    S2E_DDTSEARCHER_COMMAND Command;
    Command.Command = SEARCHER_PUSH_CONTEXT;
    Command.ContextName = (UINT_PTR) Name;

    S2EInvokePlugin("DDTSearcher", &Command, sizeof(Command));
}

static VOID S2ESearcherPopContext()
{
    S2E_DDTSEARCHER_COMMAND Command;
    Command.Command = SEARCHER_POP_CONTEXT;
    Command.ContextName = 0;

    S2EInvokePlugin("DDTSearcher", &Command, sizeof(Command));
}

static VOID S2ESetPhaseNumber(UINT64 PhaseNumber)
{
    S2E_DDTSEARCHER_COMMAND Command;
    Command.Command = SEARCHER_SET_PHASE;
    Command.PhaseNumber = (UINT_PTR) PhaseNumber;

    S2EInvokePlugin("DDTSearcher", &Command, sizeof(Command));
}

#endif