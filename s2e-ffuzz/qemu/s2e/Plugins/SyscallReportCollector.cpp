///
/// Copyright (C) 2015-2016, Cyberhaven, Inc
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
#include "QEMUEvents.h"

#include "SyscallReportCollector.h"

//#define DEBUG_SYSCALL

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(SyscallReportCollector, "SyscallReportCollector S2E plugin", "",
                  "ProcessExecutionDetector", "WindowsMonitor2", "Vmi");

void SyscallReportCollector::initialize()
{
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_monitor = s2e()->getPlugin<WindowsMonitor2>();
    m_vmi = s2e()->getPlugin<Vmi>();
    m_cfi = s2e()->getPlugin<SimpleCFIChecker>();
    m_modules = s2e()->getPlugin<ModuleMap>();

    ConfigFile *cfg = s2e()->getConfig();

    /**
     * Report syscalls only if the specified modules are on the thread's stack.
     */
    auto filterByModules = cfg->getStringList(getConfigKey() + ".filterByModules");
    if (filterByModules.size() > 0) {
        if (filterByModules.size() > 1) {
            getWarningsStream() << "More than one filter module is unsupported\n";
            exit(-1);
        }

        if (!m_cfi || !m_modules) {
            getWarningsStream() << "Please enable SimpleCFIChecker and ModuleMap when using filterByModules\n";
        }

        m_filterByModule = true;
        m_filterModuleName = filterByModules[0];
    }

    m_monitor->onProcessLoad.connect(
            sigc::mem_fun(*this,
                    &SyscallReportCollector::onProcessLoad)
            );

    m_monitor->onSyscall.connect(
            sigc::mem_fun(*this,
                    &SyscallReportCollector::onWindowsSyscall)
            );

    s2e()->getCorePlugin()->onTimer.connect(
            sigc::mem_fun(*this,
                    &SyscallReportCollector::onTimer)
            );

    m_counter = 0;
}


void SyscallReportCollector::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName)
{
    uint64_t parentPid = m_monitor->getProcessParent(state, pid);
    if (!m_detector->isTracked(state, parentPid)) {
        return;
    }

    /**
     * XXX: properly handle the case when the process creates legitimate
     * subprocesses (e.g., Adobe Reader spawns a sandbox).
     * If a malicious payload has the same name as a legitimate process,
     * this will miss it.
     *
     * TODO: ImageFileName should contain the full path to avoid this kind
     * of problem. Unfortunately, Windows doesn't passs it.
     */
    if (m_detector->isTracked(ImageFileName)) {
        return;
    }


    getDebugStream(state) << "Process " << hexval(parentPid)
                          << " spawned a child " << hexval(pid)
                          << " " << ImageFileName << "\n";

    if (!g_s2e_state || !monitor_ready()) {
        return;
    }

    QDict *info = qdict_new();

    qdict_put_obj(info, "name", QOBJECT(qstring_from_str(ImageFileName.c_str())));
    qdict_put_obj(info, "pid", QOBJECT(qint_from_int(pid)));
    qdict_put_obj(info, "parent_pid", QOBJECT(qint_from_int(parentPid)));

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("process_creation"))));
    data.push_back(std::make_pair("info", QOBJECT(info)));
    QEMUEvents::emitQMPEvent(this, data);
}

void SyscallReportCollector::onWindowsSyscall(S2EExecutionState *state, uint64_t pc, uint64_t syscallId, uint64_t stack)
{
    if (!m_detector->isTrackedPc(state, pc)) {
        return;
    }

    bool found = true;

    if (m_filterByModule) {
        uint64_t pid = m_monitor->getCurrentProcessId(state);
        const ModuleDescriptor *md = m_modules->getModule(state, pid, m_filterModuleName);
        if (!md) {
            return;
        }

        /**
         * We rely on the CFI checker to keep track of the set of addresses
         * on the current thread's stack. The first address found is not necessarily
         * the top-most on the stack.
         */
        found = false;
        const AddressMap &am = m_cfi->getAddressMap(state);
        for (auto it: am) {
            uint64_t address = it.first;
            if (md->LoadBase <= address && address < md->LoadBase + md->Size) {
                found = true;
                break;
            }
        }
    }

    if (found) {
        #ifdef DEBUG_SYSCALL
        uint64_t address;
        std::string name;
        uint64_t checksum = m_monitor->getKernelStruct().KernelChecksum;
        if (!m_vmi->getSyscallInfo(checksum, syscallId, address, name)) {
            getDebugStream(state) << "syscall " << hexval(syscallId) << "\n";
        } else {
            getDebugStream(state) << "syscall " << name << "\n";
        }
        #endif

        ++m_syscallCountStats[syscallId];
        m_changed = true;
    }
}

void SyscallReportCollector::reportSyscalls()
{
    QDict *info = qdict_new();

    uint64_t checksum = m_monitor->getKernelStruct().KernelChecksum;

    getDebugStream() << "syscalls called: " << m_syscallCountStats.size() << "\n";

    if (!g_s2e_state || !monitor_ready() || !m_changed) {
        return;
    }

    for (auto it:m_syscallCountStats) {
        uint64_t address;
        std::string name;
        /* unknown syscalls are for those defined by win32k.sys */
        if (!m_vmi->getSyscallInfo(checksum, it.first, address, name)) {
            name = "<unknown>";
        }

       qdict_put_obj(info, name.c_str(), QOBJECT(qint_from_int(it.second)));
    }

    QEMUEvents::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("stats"))));
    data.push_back(std::make_pair("info", QOBJECT(info)));
    QEMUEvents::emitQMPEvent(this, data);
}

void SyscallReportCollector::onTimer()
{
    ++m_counter;
    if (m_counter < 5) {
        return;
    }

    reportSyscalls();
}

} // namespace plugins
} // namespace s2e
