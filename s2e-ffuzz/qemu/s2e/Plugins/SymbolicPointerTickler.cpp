///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>

#include <llvm/Support/CommandLine.h>

#include "SymbolicPointerTickler.h"

extern llvm::cl::opt<bool> ConcolicMode;

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(SymbolicPointerTickler, "Plugin for finding bugs caused by symbolic pointers", "");

void SymbolicPointerTickler::initialize()
{
    if (ConcolicMode) {
        getWarningsStream() << "Concolic mode not supported\n";
        exit(-1);
    }

    s2e()->getCorePlugin()->onSymbolicAddress.connect(
            sigc::mem_fun(*this, &SymbolicPointerTickler::onSymbolicAddress));
}

void SymbolicPointerTickler::onSymbolicAddress(S2EExecutionState *state,
                                               klee::ref<klee::Expr> virtualAddress,
                                               uint64_t concreteAddress,
                                               bool &concretize,
                                               CorePlugin::symbolicAddressReason reason)
{
    Solver *solver = s2e()->getExecutor()->getSolver(*state);
    Query query(state->constraints, virtualAddress);
    auto range = solver->getRange(query);
    getDebugStream() << "Lower: " << range.first << " Upper: " << range.second << "\n";
}

} // namespace plugins
} // namespace s2e
