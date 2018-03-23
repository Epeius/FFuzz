///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_StackClustering_H
#define S2E_PLUGINS_StackClustering_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/CallTree.h>
#include <s2e/Plugins/StackMonitor.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/ControlFlowGraph.h>
#include <s2e/Plugins/OSMonitor.h>

namespace s2e {
namespace plugins {

class StackClustering : public Plugin
{
    S2E_PLUGIN
public:
    StackClustering(S2E* s2e): Plugin(s2e) {}

    void initialize();


private:
    typedef calltree::CallTree<S2EExecutionState*> StateCallTree;

    StackMonitor *m_stackMonitor;
    ModuleExecutionDetector *m_detector;
    ControlFlowGraph *m_cfg;
    StateCallTree m_callTree;
    OSMonitor *m_monitor;

    unsigned m_timer;
    unsigned m_interval;

    void computeCallStack(S2EExecutionState *originalState, calltree::CallStack &cs, calltree::Location &loc);

    void onStateFork(S2EExecutionState *originalState,
                      const std::vector<S2EExecutionState*>& newStates,
                      const std::vector<klee::ref<klee::Expr> >& newConditions);

    void onTimer();

    void onUpdateStates(S2EExecutionState *state,
                         const klee::StateSet &addedStates,
                         const klee::StateSet &removedStates);
public:
    StateCallTree &getCallTree() {
        return m_callTree;
    }

    void add(S2EExecutionState *state);

    void print();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_StackClustering_H
