///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_RecipeMemHelpers_H_
#define S2E_PLUGINS_RecipeMemHelpers_H_

#include <unordered_set>
#include "Recipe.h"

namespace s2e {
namespace plugins {
namespace recipe {

void FindMemoryPages(
        const CGCMonitor::MemoryMap &map,
        bool mustBeWritable, bool mustBeExecutable,
        std::unordered_set<uint64_t> &pages);

void FindSequencesOfSymbolicData(
        const klee::BitArray *concreteMask,
        uint64_t baseAddr,
        AddrSize *prevItem,
        std::vector<AddrSize> &sequences);

void FindSequencesOfSymbolicData(
        S2EExecutionState *state,
        const CGCMonitor::MemoryMap &map,
        bool mustBeExecutable,
        std::vector<AddrSize> &symbolicSequences);


}
}
}

#endif
