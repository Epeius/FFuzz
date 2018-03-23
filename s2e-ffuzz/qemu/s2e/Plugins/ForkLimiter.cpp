///
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include "ForkLimiter.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ForkLimiter, "Limits how many times each instruction in a module can fork", "",
                  "ModuleExecutionDetector");

void ForkLimiter::initialize()
{
    m_detector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));

    s2e()->getCorePlugin()->onTimer.connect(
            sigc::mem_fun(*this, &ForkLimiter::onTimer));

    s2e()->getCorePlugin()->onProcessForkDecide.connect(
            sigc::mem_fun(*this, &ForkLimiter::onProcessForkDecide));


    //Limit of forks per program counter, -1 means don't care
    m_limit = s2e()->getConfig()->getInt(getConfigKey() + ".maxForkCount", 10);
    if ((int) m_limit != -1) {
        s2e()->getCorePlugin()->onStateForkDecide.connect(
                sigc::mem_fun(*this, &ForkLimiter::onStateForkDecide));

        s2e()->getCorePlugin()->onStateFork.connect(
                sigc::mem_fun(*this, &ForkLimiter::onFork));
    }

    //Wait 5 seconds before allowing an S2E instance to fork
    m_processForkDelay = s2e()->getConfig()->getInt(getConfigKey() + ".processForkDelay", 5);

    m_timerTicks = 0;
}


void ForkLimiter::onStateForkDecide(S2EExecutionState *state, bool *doFork)
{
    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    uint64_t curPc = module->ToNativeBase(state->getPc());

    if (m_forkCount[module->Name][curPc] > m_limit) {
        *doFork = false;
    }
}

void ForkLimiter::onFork(S2EExecutionState *state,
            const std::vector<S2EExecutionState*>& newStates,
            const std::vector<klee::ref<klee::Expr> >& newConditions
            )
{
    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    if (!module) {
        return;
    }

    uint64_t curPc = module->ToNativeBase(state->getPc());
    ++m_forkCount[module->Name][curPc];
}


void ForkLimiter::onProcessForkDecide(bool *proceed)
{
    //Rate-limit forking
    if (m_timerTicks < m_processForkDelay) {
        *proceed = false;
        return;
    }

    m_timerTicks = 0;
}

void ForkLimiter::onTimer()
{
    ++m_timerTicks;
}


} // namespace plugins
} // namespace s2e
