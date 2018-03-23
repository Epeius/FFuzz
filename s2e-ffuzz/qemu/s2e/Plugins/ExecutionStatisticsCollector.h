///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_ExecutionStatistics_H
#define S2E_PLUGINS_ExecutionStatistics_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Synchronization.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/StringMap.h>

namespace s2e {
namespace plugins {

struct ExecutionStatistics {
    /**
     * How many times did the execution reach a state in which no
     * modules of interest were being executed?
     */
    unsigned emptyCallStacksCount;

    /**
     * Annotations increment this in case they detect that
     * the invocation of a library function failed.
     */
    unsigned libraryCallFailures;

    /**
     * Annotations increment this in case they detect that
     * the invocation of a library function succeeded.
     */
    unsigned libraryCallSuccesses;

    /**
     *  How many artificial values were injected by annotations.
     */
    unsigned injectionCount;

    /**
     *  Counts the number of times modules of interest were loaded.
     */
    unsigned moduleLoads;

    typedef llvm::DenseMap<uint64_t, unsigned> FunctionInvocationCount;
    FunctionInvocationCount entryPointInvocationCount;

    /** Stores module names and relative program counters */
    typedef std::map<std::string, FunctionInvocationCount> FunctionInvocationCountByModule;
    FunctionInvocationCountByModule entryPointInvocationCountByModule;

    ExecutionStatistics() {
        emptyCallStacksCount = 0;
        libraryCallFailures = 0;
        libraryCallSuccesses = 0;
        injectionCount = 0;
        moduleLoads = 0;
    }


};

class ExecutionStatisticsCollectorState:public PluginState
{
private:
    ExecutionStatistics m_stats;

public:

    ExecutionStatisticsCollectorState() {}

    virtual ~ExecutionStatisticsCollectorState() {}

    virtual ExecutionStatisticsCollectorState* clone() const {
        return new ExecutionStatisticsCollectorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ExecutionStatisticsCollectorState;
    }

    ExecutionStatistics &getStatistics() {
        return m_stats;
    }
};

class ExecutionStatisticsCollector : public Plugin
{
    S2E_PLUGIN
public:
    ExecutionStatisticsCollector(S2E* s2e): Plugin(s2e) {}

    void initialize();

    ExecutionStatistics &getStatistics(S2EExecutionState *state) const {
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        return plgState->getStatistics();
    }

    ExecutionStatistics &getStatistics() {
        return m_globalStats;
    }

    void incrementInjections(S2EExecutionState *state) {
        ++m_globalStats.libraryCallFailures;
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        ++plgState->getStatistics().libraryCallFailures;
    }

    void incrementLibCallFailures(S2EExecutionState *state) {
        ++m_globalStats.libraryCallFailures;
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        ++plgState->getStatistics().libraryCallFailures;
    }

    void incrementLibCallSuccesses(S2EExecutionState *state) {
        ++m_globalStats.libraryCallSuccesses;
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        ++plgState->getStatistics().libraryCallSuccesses;
    }

    void incrementEmptyCallStacksCount(S2EExecutionState *state) {
        ++m_globalStats.emptyCallStacksCount;
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        ++plgState->getStatistics().emptyCallStacksCount;
    }

    void incrementEntryPointCall(S2EExecutionState *state, uint64_t ep) {
        ++m_globalStats.entryPointInvocationCount[ep];
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        ++plgState->getStatistics().entryPointInvocationCount[ep];
    }

    void incrementEntryPointCallForModule(S2EExecutionState *state) {
        uint64_t pc = state->getPc();
        const ModuleDescriptor* desc;

        incrementEntryPointCall(state, pc);
        if (m_detector && (desc = m_detector->getCurrentDescriptor(state))) {

            uint64_t relPc = desc->ToNativeBase(pc);
            ++m_globalStats.entryPointInvocationCountByModule[desc->Name][relPc];

            DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
            ++plgState->getStatistics().entryPointInvocationCountByModule[desc->Name][relPc];
        }
    }

    unsigned getEntryPointCallCountForModule(S2EExecutionState *state) {
        uint64_t pc = state->getPc();
        const ModuleDescriptor* desc;

        if (m_detector && (desc = m_detector->getCurrentDescriptor(state))) {
            uint64_t relPc = desc->ToNativeBase(pc);
            DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
            return plgState->getStatistics().entryPointInvocationCountByModule[desc->Name][relPc];
        } else {
            return 0;
        }
    }

    unsigned getTotalEntryPointCallCountForModule(S2EExecutionState *state) {
        uint64_t pc = state->getPc();
        const ModuleDescriptor* desc;

        if (m_detector && (desc = m_detector->getCurrentDescriptor(state))) {
            uint64_t relPc = desc->ToNativeBase(pc);
            return m_globalStats.entryPointInvocationCountByModule[desc->Name][relPc];
        } else {
            return 0;
        }
    }

    void incrementModuleLoads(S2EExecutionState *state) {
        ++m_globalStats.moduleLoads;
        DECLARE_PLUGINSTATE(ExecutionStatisticsCollectorState, state);
        ++plgState->getStatistics().moduleLoads;
    }

private:
    ExecutionStatistics m_globalStats;
    ModuleExecutionDetector *m_detector;

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ExecutionStatistics_H
