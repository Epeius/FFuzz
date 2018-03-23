///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_STACKCHECKER_H
#define S2E_PLUGINS_STACKCHECKER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include "StackMonitor.h"
#include "MemoryChecker.h"
#include "OSMonitor.h"

namespace s2e {
namespace plugins {

class StackChecker : public Plugin
{
    S2E_PLUGIN
public:
    StackChecker(S2E* s2e): Plugin(s2e) {}

    void initialize();


private:
    StackMonitor *m_stackMonitor;
    MemoryChecker *m_memoryChecker;
    OSMonitor *m_monitor;

    void onMemoryAccess(S2EExecutionState *state, uint64_t address,
                        unsigned size, bool isWrite, bool *result);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_STACKCHECKER_H
