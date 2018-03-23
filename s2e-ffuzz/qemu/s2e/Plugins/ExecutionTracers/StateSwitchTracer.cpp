///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2E.h>

#include "StateSwitchTracer.h"
#include "TraceEntries.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StateSwitchTracer, "Traces state switches", "", "ExecutionTracer");

void StateSwitchTracer::initialize()
{
    m_tracer = static_cast<ExecutionTracer*>(s2e()->getPlugin("ExecutionTracer"));

    s2e()->getCorePlugin()->onStateSwitch.connect(
            sigc::mem_fun(*this, &StateSwitchTracer::onStateSwitch));
}

void StateSwitchTracer::onStateSwitch(S2EExecutionState *currentState,
                                      S2EExecutionState *nextState)
{
    ExecutionTraceStateSwitch e;
    e.newStateId = nextState->getID();

    m_tracer->writeData(currentState, &e, sizeof(e), TRACE_STATE_SWITCH);
}


} // namespace plugins
} // namespace s2e
