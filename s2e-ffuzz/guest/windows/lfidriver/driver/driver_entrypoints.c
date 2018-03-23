#include <ntddk.h>
#include <ntstrsafe.h>
#include <hook.h>
#include <s2e.h>
#include <searcher.h>
#include <keyvalue.h>
#include <symbhw.h>
#include <ResourceTracker.h>

static NTSTATUS S2EHook_DriverEntry(
                DRIVER_INITIALIZE Original,
                IN PDRIVER_OBJECT DriverObject,
                IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Result;

    S2EMessageFmt("MAIN ENTRY POINT CALLED: %s\n", __FUNCTION__);
    S2ESearcherPushContext(__FUNCTION__);

    Result = Original(DriverObject, RegistryPath);

    S2ESearcherPopContext();

    S2EMessageFmt("MAIN ENTRY POINT RETURNED: %s\n", __FUNCTION__);

    if (!NT_SUCCESS(Result)) {
        S2EResourceTrackerReportLeaks((UINT64) Original);

        if (S2EGetPathCount() > 1) {
            S2EKillState(Result, "MAIN ENTRY POINT failed");
        } else {
            BOOLEAN NewKey;
            S2EMessage("ENTRY POINT InitializeHandler failed while in last state");
            //S2EKVSSetValue("all_failed", 1, &NewKey);
            S2EMessageFmt("No faults in this path, will try another hw config\n");
            SymbhwNotifyTestScriptToLoadNextConfig();
            SymbHwActivateSymbolicPciBus(FALSE);
        }
    }

    //Register all IRP_MJ_*** entry points here

    return Result;
}

VOID S2ERegisterMainEntryPointHook(VOID)
{
    S2ERegisterDriverEntryPoint(0, "DriverEntry", NULL, S2EHook_DriverEntry);
}