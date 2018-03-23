///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#ifndef SIMPLECFIREPORTCOLLECTOR_H
#define SIMPLECFIREPORTCOLLECTOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <string>

#include "SimpleCFIChecker.h"

#include <s2e/Plugins/ExecutionTracers/UserSpaceTracer.h>
#include <s2e/Plugins/BaseInstructions.h>
#include <s2e/Plugins/ModuleMap.h>
#include <s2e/Plugins/WindowsMonitor2.h>

namespace s2e {
namespace plugins {


enum S2E_CFI_REPORT_COLLECTOR_COMMANDS {
    CPU_USAGE,
    AUTOSCROLL_DONE,
    MAIN_WINDOW_OPEN
};

struct S2E_CFI_RC_CPU {
    uint32_t TotalCpuUsage;
    uint32_t ProgramCpuUsage;
};

struct S2E_CFI_REPORT_COLLECTOR_COMMAND {
    S2E_CFI_REPORT_COLLECTOR_COMMANDS Command;
    S2E_CFI_RC_CPU CpuUsage; //CPU Usage in %
};


class SimpleCFIReportCollector : public Plugin, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN
public:
    SimpleCFIReportCollector(S2E* s2e): Plugin(s2e) {}

    void initialize();

private:
    SimpleCFIChecker *m_cfi_checker;
    UserSpaceTracer *m_tracer;
    ModuleMap *m_modules;
    WindowsMonitor2 *m_monitor;
    bool m_traceOnReturnViolation;

    uint64_t m_timerCount;
    bool m_monitorIdleAfterAutoscroll;

    S2E_CFI_RC_CPU m_averageCpuUsage;
    unsigned m_cpuUsageIterations;
    bool m_ticklerStarted;
    unsigned m_autoscrollDoneCount;
    bool m_mainWindowOpen;

    bool m_generateDumpOnFirstViolation;
    unsigned m_cpuUsageThreshold;

    uint64_t m_heapSprayingThreshold;

    void onTimer(void);
    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);
    void onCFIViolation(S2EExecutionState* state, bool isReturnViolation);
    void onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault);
    void onFYINotification(S2EExecutionState *state, std::string info);
    void onWindowInfo(S2EExecutionState *state, std::string info);
    void onAllProcessesTerminated(S2EExecutionState *state);

    void stopIfTooManyCFIViolations(S2EExecutionState *state);
    void stopIfSegfaultDetected(S2EExecutionState *state);
    void stopIfIdle(S2EExecutionState *state);

    void updateAverageCpuUsage(S2EExecutionState *state, const S2E_CFI_RC_CPU &usage);

    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e


#endif // SIMPLECFIREPORTCOLLECTOR_H
