///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


extern "C" {
#include <qstring.h>
}

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <vmi/ntddk.h>

#include "QEMUEvents.h"
#include "SimpleCFIReportCollector.h"
#include <s2e/Plugins/WindowsInterceptor/WindowsCrashDumpGenerator.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(SimpleCFIReportCollector, "Simple CFI Report Collector S2E plugin", "", "SimpleCFIChecker", "ModuleMap", "WindowsMonitor2");


void SimpleCFIReportCollector::initialize()
{

    m_cfi_checker = s2e()->getPlugin<SimpleCFIChecker>();

    m_generateDumpOnFirstViolation = s2e()->getConfig()->getBool(getConfigKey() + ".generateDumpOnFirstViolation");
    m_cpuUsageThreshold = s2e()->getConfig()->getInt(getConfigKey() + ".cpuUsageThreshold", 10);
    if (m_cpuUsageThreshold > 100) {
        getWarningsStream() << "Invalid CPU usage threshold\n";
        exit(-1);
    }

    m_heapSprayingThreshold = s2e()->getConfig()->getInt(getConfigKey() + ".heapSprayingThreshold", -1);

    m_cfi_checker->onCFIViolationDetected.connect(
                sigc::mem_fun(*this,
                              &SimpleCFIReportCollector::onCFIViolation)
                );

    m_cfi_checker->onCFIAccessFault.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIReportCollector::onAccessFault)
            );

    m_cfi_checker->onFYISignal.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIReportCollector::onFYINotification)
            );

    m_cfi_checker->onWindowTextSignal.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIReportCollector::onWindowInfo)
            );

    m_cfi_checker->onAllProcessesTerminated.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIReportCollector::onAllProcessesTerminated)
            );

    s2e()->getCorePlugin()->onTimer.connect(
            sigc::mem_fun(*this, &SimpleCFIReportCollector::onTimer));

    m_tracer = s2e()->getPlugin<UserSpaceTracer>();
    m_modules = s2e()->getPlugin<ModuleMap>();
    m_monitor = s2e()->getPlugin<WindowsMonitor2>();

    m_monitor->onProcessLoad.connect(
            sigc::mem_fun(*this,
                    &SimpleCFIReportCollector::onProcessLoad)
            );

    m_traceOnReturnViolation = s2e()->getConfig()->getBool(getConfigKey() + ".traceOnReturnViolation", false);

    if (m_traceOnReturnViolation) {
        if (!m_tracer) {
            getDebugStream() << "SimpleCFIReportCollector: "
                                    << "traceOnReturnViolation requires UserSpaceTracer\n";
            exit(-1);
        }
    }

    /**
     * When enabled, waits for the autoscroll done signal to monitor for idle CPU.
     * When disabled, wait for idle CPU after the tickler is loaded.
     */
    m_monitorIdleAfterAutoscroll = s2e()->getConfig()->getBool(getConfigKey() + ".monitorIdleAfterAutoscroll", false);

    m_timerCount = 0;
    m_averageCpuUsage.ProgramCpuUsage = 0;
    m_averageCpuUsage.TotalCpuUsage = 0;
    m_cpuUsageIterations = 0;
    m_autoscrollDoneCount = 0;
    m_ticklerStarted = false;
}

void SimpleCFIReportCollector::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName)
{
    if (ImageFileName == "tickler.exe") {
        getDebugStream(state) << "Tickler started\n";
        m_ticklerStarted = true;
    }
}

void SimpleCFIReportCollector::onCFIViolation(S2EExecutionState* state, bool isReturnViolation)
{
    //Take a crash dump on first occurence
    WindowsCrashDumpGenerator *dmp = s2e()->getPlugin<WindowsCrashDumpGenerator>();
    if (m_generateDumpOnFirstViolation && dmp) {
        vmi::windows::BugCheckDescription desc;
        dmp->generateManualDump(state, dmp->getPathForDump(state), &desc);
        m_generateDumpOnFirstViolation = false;
    }

    if (!g_s2e_state) {
        return;
    }

    if (m_traceOnReturnViolation && isReturnViolation && m_tracer) {
        m_tracer->startTracing(state);
    }

    if (!monitor_ready()) {
        return;
    }

    QEMUEvents::PluginData data;
    //XXX: replace with more informative string coming from the SimpleCFIChecker plugin
    QString *str = qstring_from_str("cfi_violation");
    data.push_back(std::make_pair("type", QOBJECT(str)));
    QEMUEvents::emitQMPEvent(this, data);
}

void SimpleCFIReportCollector::onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault)
{

    uint64_t pc, sp;
    QDict *info = m_monitor->getTrapInformation(state, AccessFault.TrapInformation, &pc, &sp);
    QEMUEvents::printDict(this, info);
    QDECREF(info);

    const ModuleDescriptor *module = m_modules->getModule(state, pc);
    if (module) {
        getDebugStream(state) << "Fault at " << module->Name << ":" << hexval(module->ToNativeBase(pc)) << "\n";
    }

    const ModuleDescriptor *ramod = m_modules->getModule(state, AccessFault.ReturnAddress);
    uint64_t ra = AccessFault.ReturnAddress;
    if (ramod) {
        ra = ramod->ToNativeBase(AccessFault.ReturnAddress);
    }
    getDebugStream(state) << "MmAccessFault ra=" << hexval(ra) << "\n";

    //TODO: dump the stack


    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("access_fault"))));

    QDict *info_dict = qdict_new();
    qdict_put_obj(info_dict, "status_code", QOBJECT(qint_from_int(AccessFault.StatusCode)));
    qdict_put_obj(info_dict, "address", QOBJECT(qint_from_int(AccessFault.Address)));
    qdict_put_obj(info_dict, "pc", QOBJECT(qint_from_int(pc)));
    if (module) {
        qdict_put_obj(info_dict, "module", QOBJECT(qstring_from_str(module->Name.c_str())));
        qdict_put_obj(info_dict, "base", QOBJECT(qint_from_int(module->ToNativeBase(pc))));
    }

    data.push_back(std::make_pair("info", QOBJECT(info_dict)));
    QEMUEvents::emitQMPEvent(this, data);
}


void SimpleCFIReportCollector::onFYINotification(S2EExecutionState *state, std::string info)
{
    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("fyi"))));
    data.push_back(std::make_pair("info", QOBJECT(qstring_from_str(info.c_str()))));
    QEMUEvents::emitQMPEvent(this, data);
}

void SimpleCFIReportCollector::onAllProcessesTerminated(S2EExecutionState *state)
{
    onFYINotification(state, "application terminated unexpectedly");

    getDebugStream(state) << "Finishing because all tracked processes terminated\n";
    m_cfi_checker->stopAnalysis(state);
}

void SimpleCFIReportCollector::onWindowInfo(S2EExecutionState *state, std::string info)
{
    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("window_text"))));
    data.push_back(std::make_pair("info", QOBJECT(qstring_from_str(info.c_str()))));
    QEMUEvents::emitQMPEvent(this, data);
}


/* Print stats periodically */
void SimpleCFIReportCollector::onTimer(void)
{
    static bool highMemoryUsageNotified = false;

    if (m_timerCount < 10) {
        ++m_timerCount;
        return;
    }

    m_timerCount = 0;

    QDict *stats = m_cfi_checker->getStatistics(g_s2e_state);


    QEMUEvents::printDict(this, stats);

    if (!g_s2e_state || !monitor_ready()) {
        QDECREF(stats);
    } else {
        QEMUEvents::PluginData data;
        data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("stats"))));
        data.push_back(std::make_pair("data", QOBJECT(stats)));
        QEMUEvents::emitQMPEvent(this, data);
    }

    uint64_t memUsage = m_cfi_checker->getStatistic(g_s2e_state, "peak_commit_charge");
    if (memUsage >= m_heapSprayingThreshold) {
        if (!highMemoryUsageNotified) {
            onFYINotification(g_s2e_state, "high memory usage");
            highMemoryUsageNotified = true;
        }
    }

    stopIfTooManyCFIViolations(g_s2e_state);
    stopIfSegfaultDetected(g_s2e_state);
    stopIfIdle(g_s2e_state);
}

void SimpleCFIReportCollector::stopIfTooManyCFIViolations(S2EExecutionState *state)
{
    #define MAX_VIOLATIONS_BEFORE_STOPPING 20

    uint64_t faultCount = 0;
    faultCount += m_cfi_checker->getStatistic(state, "call_violation_count");
    faultCount += m_cfi_checker->getStatistic(state, "ret_violation_count");

    if (faultCount > MAX_VIOLATIONS_BEFORE_STOPPING) {
        getWarningsStream(state) << "stopping after "
                                        << MAX_VIOLATIONS_BEFORE_STOPPING << "\n";
        m_cfi_checker->stopAnalysis(state);
    }
}


void SimpleCFIReportCollector::stopIfSegfaultDetected(S2EExecutionState *state) {
    static unsigned count = 0;

    uint64_t faultCount = 0;
    faultCount += m_cfi_checker->getStatistic(state, "seg_fault_count");
    faultCount += m_cfi_checker->getStatistic(state, "wer_fault_count");

    if (faultCount == 0) {
        return;
    }

    //wait a few timer ticks before deciding whether to stop
    if ((count++) < 2) {
        return;
    }

    getWarningsStream(state) << "got at least one segfault, stopping analysis\n";

    m_cfi_checker->stopAnalysis(state);
}

void SimpleCFIReportCollector::stopIfIdle(S2EExecutionState *state)
{
    static unsigned count = 0;

    if (!m_ticklerStarted) {
        /* Tickler may take a long time to load, wait before killing */
        return;
    }

    if (!m_mainWindowOpen) {
        /* Main window of the tracked app may take a long time to load, wait before killing */
        return;
    }

    if (m_monitorIdleAfterAutoscroll && !m_autoscrollDoneCount) {
        /* Autoscroll not done yet, don't check for idle */
        return;
    }

    if (m_averageCpuUsage.ProgramCpuUsage > m_cpuUsageThreshold) {
        /* Cpu usage too high, keep waiting */
        count = 0;
        return;
    }

    /**
     * Some exploits become idle after doing heap spraying, prematurely
     * killing the analysis. This tries to detect cases of high memory
     * usage that could be indicative of heap spraying, and increases the
     * timeout.
     */
    unsigned defaultTimeout = 1; //20 seconds
    uint64_t memUsage = m_cfi_checker->getStatistic(state, "peak_commit_charge");
    if (memUsage >= m_heapSprayingThreshold) {
        getDebugStream(state) << "Peak commit charge high, suspecting heap spraying\n";
        defaultTimeout = 20;
    }

    if (m_monitorIdleAfterAutoscroll && m_autoscrollDoneCount) {
        if (count > defaultTimeout) {
            getDebugStream(state) << "Finishing because idle after autoscroll\n";
            m_cfi_checker->stopAnalysis(state);
            return;
        }
    }

    if (count > std::max<uint64_t>(20, defaultTimeout)) { //200 secs
        //Sometimes, autoscroll is not properly notified.
        //This catches long idle periods.
        getDebugStream(state) << "Finishing because idle too long\n";
        m_cfi_checker->stopAnalysis(state);
        return;
    }

    ++count;
}

void SimpleCFIReportCollector::updateAverageCpuUsage(S2EExecutionState *state, const S2E_CFI_RC_CPU &usage)
{

    static const double MOVING_AVERAGE_ALPHA = 0.1;

    if (!m_cpuUsageIterations) {
        m_averageCpuUsage = usage;
    } else {
        m_averageCpuUsage.ProgramCpuUsage = (1.0 - MOVING_AVERAGE_ALPHA) * (double) m_averageCpuUsage.ProgramCpuUsage + MOVING_AVERAGE_ALPHA * (double) usage.ProgramCpuUsage;
        m_averageCpuUsage.TotalCpuUsage = (1.0 - MOVING_AVERAGE_ALPHA) * (double) m_averageCpuUsage.TotalCpuUsage + MOVING_AVERAGE_ALPHA * (double) usage.TotalCpuUsage;
    }

    ++m_cpuUsageIterations;

    getDebugStream(state) << "Current CPU Usage: " << usage.ProgramCpuUsage << "% / " << usage.TotalCpuUsage << "%"
                          << " AVG Total: " << (unsigned) m_averageCpuUsage.TotalCpuUsage << "%"
                          << " AVG Program: " << (unsigned) m_averageCpuUsage.ProgramCpuUsage << "%"
                          << "\n";
}

void SimpleCFIReportCollector::handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize)
{
    S2E_CFI_REPORT_COLLECTOR_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) <<
                "mismatched S2E_CFI_REPORT_COLLECTOR_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) <<
                "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case CPU_USAGE: {
            updateAverageCpuUsage(state, command.CpuUsage);
        } break;

        case AUTOSCROLL_DONE: {
            ++m_autoscrollDoneCount;
            getDebugStream(state) << "Autoscroll done\n";
        } break;

        case MAIN_WINDOW_OPEN: {
            m_mainWindowOpen = true;
            getDebugStream(state) << "Main window open\n";
        } break;
    }
}

} // namespace plugins
} // namespace s2e

