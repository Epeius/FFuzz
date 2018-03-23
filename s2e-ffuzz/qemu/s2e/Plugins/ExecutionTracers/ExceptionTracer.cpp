///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "ExceptionTracer.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include "TraceEntries.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExceptionTracer, "Traces CPU exception", "", "ExecutionTracer");

void ExceptionTracer::initialize()
{
    m_tracer = static_cast<ExecutionTracer*>(s2e()->getPlugin("ExecutionTracer"));

    s2e()->getCorePlugin()->onException.connect(
            sigc::mem_fun(*this, &ExceptionTracer::onException));
}

void ExceptionTracer::onException(S2EExecutionState *state,
                                  unsigned vec, uint64_t pc)
{
    ExecutionTraceException e;
    e.pc = state->getPc();
    e.vector = vec;

    m_tracer->writeData(state, &e, sizeof(e), TRACE_EXCEPTION);
}


} // namespace plugins
} // namespace s2e
