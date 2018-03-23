///
/// Copyright (C) 2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_FunctionMonitor2_H
#define S2E_PLUGINS_FunctionMonitor2_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/WindowsMonitor2.h>
#include <s2e/Plugins/ProcessExecutionDetector.h>
#include <s2e/Plugins/ModuleMap.h>
#include <s2e/Plugins/ExecutionTracers/TranslationBlockTracer.h>

#include <llvm/ADT/SmallVector.h>

namespace s2e {
namespace plugins {

class FunctionMonitor2 : public Plugin
{
    S2E_PLUGIN
public:
    FunctionMonitor2(S2E* s2e): Plugin(s2e) {}

    void initialize();

    sigc::signal<void,
                S2EExecutionState*,
                const ModuleDescriptor * /* callerModule */,
                const ModuleDescriptor * /* calleeModule */,
                uint64_t /* callerPc */,
                uint64_t /* calleePc */>
          onCall;
private:
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_processDetector;
    ModuleMap *m_map;
    ExecutionTracer *m_tracer;

    void onExecuteStart(S2EExecutionState *state, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal,
                              S2EExecutionState *state,
                              TranslationBlock *tb,
                              uint64_t pc, bool isStatic, uint64_t staticTarget);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FunctionMonitor2_H
