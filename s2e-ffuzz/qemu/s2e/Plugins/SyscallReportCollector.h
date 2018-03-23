///
/// Copyright (C) 2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SyscallReportCollector_H
#define S2E_PLUGINS_SyscallReportCollector_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/WindowsMonitor2.h>
#include <s2e/Plugins/Vmi.h>
#include <s2e/Plugins/ModuleMap.h>
#include <s2e/Plugins/ProcessExecutionDetector.h>
#include <s2e/Plugins/SimpleCFIChecker.h>

#include <llvm/ADT/DenseMap.h>

namespace s2e {
namespace plugins {

class SyscallReportCollector : public Plugin
{
    S2E_PLUGIN
public:
    SyscallReportCollector(S2E* s2e): Plugin(s2e) {}

    void initialize();


private:
    ProcessExecutionDetector *m_detector;
    WindowsMonitor2 *m_monitor;
    Vmi *m_vmi;
    SimpleCFIChecker *m_cfi;
    ModuleMap *m_modules;

    bool m_filterByModule;
    std::string m_filterModuleName;

    llvm::DenseMap<uint64_t, unsigned> m_syscallCountStats;
    unsigned m_counter;
    bool m_changed;

    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);
    void onWindowsSyscall(S2EExecutionState *state, uint64_t pc, uint64_t syscallId, uint64_t stack);

    void onTimer();
    void reportSyscalls();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SyscallReportCollector_H
