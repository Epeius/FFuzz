#include <iostream>
#include "pdh.h"
#include "TargetApp.h"
#include "Tickler.h"

#define USER_APP
extern "C" {
#include "SimpleCFIReportCollector.h"
}


static PDH_HQUERY cpuQuery;
static PDH_HCOUNTER cpuTotal;
static TargetApp* app;

static void initCPUMonitor() {
    PdhOpenQuery(NULL, NULL, &cpuQuery);

    PdhAddCounter(cpuQuery, L"\\Processor(_Total)\\% Processor Time", NULL, &cpuTotal);

    app->initCPUMonitor(cpuQuery);

    PdhCollectQueryData(cpuQuery);
}

static void cleanCPUMonitor() {
    PdhCloseQuery(cpuQuery);
}

static void getCurrentCpuUsage(PLONG Total, PLONG targets) {

    PDH_FMT_COUNTERVALUE counterVal;

    PdhCollectQueryData(cpuQuery);

    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_LONG, NULL, &counterVal);
    *Total = counterVal.longValue;

    app->getCurrentCpuUsage(Total, targets);
}

static DWORD WINAPI CpuMonitorThread(LPVOID Unused)
{

    initCPUMonitor();

    while (1) {
        LONG Total, Target;
        getCurrentCpuUsage(&Total, &Target);
        TICKLERMSG("CPU usage: %d Target %s: %d\n", Total, app->getName().c_str(), Target);
        S2EReportCpuUsage((UINT) Total, (UINT) Target);
        TargetApp::S2ESleepMs(2000);
    }

    cleanCPUMonitor();

    return 0;
}

VOID StartCpuMonitor(TargetApp *targetApp)
{
    app = targetApp;
    HANDLE hThread = CreateThread(
        NULL,                   // default security attributes
        0,                      // use default stack size  
        CpuMonitorThread,         // thread function name
        NULL,               // argument to thread function 
        0,                      // use default creation flags 
        NULL);                  // returns the thread identifier 

    if (hThread == NULL) {
        std::cout << "cannot spawn thread for delayed scrolling\n";
        TICKLERMSG("cannot spawn thread for delayed scrolling\n");
    }
}