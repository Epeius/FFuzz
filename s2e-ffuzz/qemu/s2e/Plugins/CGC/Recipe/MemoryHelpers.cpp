///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2EExecutionState.h>
#include "MemoryHelpers.h"

using namespace klee;

namespace s2e {
namespace plugins {
namespace recipe {

/// \brief findSequencesOfSymbolicData
/// Find contiguous regions of symbolic data described by an
/// AddrSize structure. Walks through all bits in concreteMask to create
/// a list of contiguous symbolic bytes.
///
/// E.g., for bitmask 1001110000 it will find 2 sequences with sizes 2 and 4
/// (0 bit means symbolic).
///
/// \param sequences The resulting list of regions
/// \param concreteMask Mask that specifies whether each byte of a region is symbolic or not
/// \param baseAddr The virtual base address of the first bit in concreteMask
/// \param prevItem Used to automatically merge sequence spanning 2 memory pages.
/// If the function is called with bitmask 111000 and then 0111, it will update previously
/// found sequence to have size 4.
///
void FindSequencesOfSymbolicData(
        const BitArray *concreteMask,
        uint64_t baseAddr,
        AddrSize *prevItem,
        std::vector<AddrSize> &sequences)
{
    unsigned maskSize = concreteMask->getBitCount();

    if (!concreteMask || concreteMask->isAllOnes(maskSize)) {
        return;
    }

    unsigned size = 0;
    unsigned offset;

    // Walk through all bits (plus one more to terminate sequence ending on page boundary)
    for (unsigned int i = 0; i <= maskSize; i++) {
        if (i != maskSize && !concreteMask->get(i)) {
            // first symbolic byte, remember its position
            if (!size) {
                offset = i;
            }

            size++;
        } else {
            // concrete byte again, nothing to do
            if (!size) {
                continue;
            }

            // symbolic sequence terminated
            if (offset == 0 && prevItem && prevItem->addr + prevItem->size == baseAddr) {
                // merge with previous sequence
                prevItem->size += size;
            } else {
                sequences.push_back(AddrSize(baseAddr + offset, size));
            }

            size = 0;
        }
    }
}

/// \brief Find contigous chunks of symbolic data in selected memory pages
///
/// \param state current state
/// \param pages memory pages where to search for symbolic data
/// \param symbolicSequences discovered sequences of symbolic data
///
static void FindSequencesOfSymbolicData(
        S2EExecutionState *state,
        const std::unordered_set<uint64_t> &pages,
        std::vector<AddrSize> &symbolicSequences)
{
    std::set<uint64_t> sortedPages(pages.begin(), pages.end());

    foreach2(it, sortedPages.begin(), sortedPages.end())
    {
        ObjectPair op = state->mem()->getMemoryObject(*it);
        if (!op.first) { // page was not used/mapped
            continue;
        }

        const BitArray *concreteMask = op.second->getConcreteMask();
        if (!concreteMask) { // all bytes are concrete
            continue;
        }

        // Even if ObjectState was split, it must use same concreteMask object.
        assert(concreteMask->getBitCount() == TARGET_PAGE_SIZE);

        // Last item from previous page (assume pages (and thus items) are sorted)
        AddrSize *prevItem = symbolicSequences.size() ? &symbolicSequences.back() : NULL;

        FindSequencesOfSymbolicData(concreteMask, *it, prevItem, symbolicSequences);
    }
}

/// \brief Find contigous chunks of symbolic data with given memory layout
///
/// \param state current state
/// \param map memory map
/// \param mustBeExecutable true if symbolic data must be executable
/// \param symbolicSequences discovered sequences of symbolic data
///
void FindSequencesOfSymbolicData(
        S2EExecutionState *state,
        const CGCMonitor::MemoryMap &map,
        bool mustBeExecutable,
        std::vector<AddrSize> &symbolicSequences)
{
    std::unordered_set<uint64_t> pages;
    CGCMonitor::FindMemoryPages(map, true, mustBeExecutable, pages);
    FindSequencesOfSymbolicData(state, pages, symbolicSequences);
}

}
}
}
