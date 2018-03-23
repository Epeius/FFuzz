#ifndef S2E_RESOURCE_TRACKER

#define S2E_RESOURCE_TRACKER

#include "s2e.h"

__declspec(align(8))
typedef struct S2E_RSRCTRK_RESOURCE {
    UINT64 ResourceId;
    UINT64 CallSite;

    /* API function that allocated/deallocated the resource */
    UINT64 LibraryName;
    UINT64 LibraryFunctionName;
} S2E_RSRCTRK_RESOURCE;

__declspec(align(8))
typedef enum S2E_RSRCTRK_COMMANDS {
    RESOURCE_ALLOCATION,
    RESOURCE_DEALLOCATION,
    REPORT_LEAKS
} S2E_RSRCTRK_COMMANDS;

__declspec(align(8))
typedef struct S2E_RSRCTRK_COMMAND {
    S2E_RSRCTRK_COMMANDS Command;
    union {
        S2E_RSRCTRK_RESOURCE Resource;
        UINT64 ModulePc;
    };
} S2E_RSRCTRK_COMMAND;


static VOID S2EAllocateResource(PCSTR LibraryFunctionName,
                         PCSTR LibraryName, UINT_PTR CallSite,
                         UINT_PTR ResourceId, BOOLEAN Allocate)
{
    S2E_RSRCTRK_COMMAND Command;
    Command.Command = Allocate ? RESOURCE_ALLOCATION : RESOURCE_DEALLOCATION;
    Command.Resource.CallSite = CallSite;
    Command.Resource.LibraryFunctionName = (UINT_PTR) LibraryFunctionName;
    Command.Resource.LibraryName = (UINT_PTR) LibraryName;
    Command.Resource.ResourceId = ResourceId;

    __s2e_touch_string(LibraryFunctionName);
    __s2e_touch_string(LibraryName);
    S2EInvokePlugin("ResourceTracker", &Command, sizeof(Command));
}

static VOID S2EResourceTrackerReportLeaks(UINT64 ModulePc)
{
    S2E_RSRCTRK_COMMAND Command;
    Command.Command = REPORT_LEAKS;
    Command.ModulePc = ModulePc;
    S2EInvokePlugin("ResourceTracker", &Command, sizeof(Command));
}

#endif