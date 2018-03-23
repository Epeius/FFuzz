///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E__NGRAM_COVERAGE_H
#define S2E__NGRAM_COVERAGE_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include "ExecutionTracer.h"
#include "TraceEntries.h"

namespace s2e {
namespace plugins {

class NGramCoverage : public Plugin
{
    S2E_PLUGIN
public:
    NGramCoverage(S2E* s2e): Plugin(s2e) {}


    void initialize(void);

private:
    ExecutionTracer *m_tracer;
    ModuleExecutionDetector *m_detector;

    std::string m_moduleName;

    int m_timerTicks;

    void onExecuteBlockStart(S2EExecutionState *state, uint64_t pc);

    void onModuleTranslateBlockStart(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t pc);

    void onStateKill(S2EExecutionState *state);

    void onTimer() {
        m_timerTicks++;
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_NGRAM_COVERAGE_H

