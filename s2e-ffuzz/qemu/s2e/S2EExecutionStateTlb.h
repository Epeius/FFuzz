///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_EXECUTION_STATE_TLB

#define S2E_EXECUTION_STATE_TLB

#include <vector>
#include <tr1/unordered_map>
#include <klee/Memory.h>
#include "AddressSpaceCache.h"
#include "S2EExecutionStateRegisters.h"

extern "C" {
    struct CPUX86State;
}

namespace s2e {


class S2EExecutionStateTlb {
public:
    /**
     * The following tracks the location of every ObjectState
     * in the TLB in order to optimize TLB updates.
     */
    typedef std::pair<unsigned int, unsigned int> TlbCoordinates;
    typedef llvm::SmallVector<TlbCoordinates, 8> ObjectStateTlbReferences;
    typedef std::tr1::unordered_map<klee::ObjectState *, ObjectStateTlbReferences> TlbMap;

private:
    TlbMap m_tlbMap;
    AddressSpaceCache *m_asCache;
    S2EExecutionStateRegisters *m_registers;

public:

    S2EExecutionStateTlb(AddressSpaceCache *ascache, S2EExecutionStateRegisters *regs) :
            m_asCache(ascache), m_registers(regs) {}

    void assignNewState(AddressSpaceCache *ascache, S2EExecutionStateRegisters *regs) {
        m_asCache = ascache;
        m_registers = regs;
    }

    /* Change all entries that refer to oldState to newState */
    void updateTlb(const klee::MemoryObject *mo,
            const klee::ObjectState *oldState, klee::ObjectState *newState);


    void addressSpaceChangeUpdateTlb(const klee::MemoryObject *mo,
                                     const klee::ObjectState *oldState,
                                     klee::ObjectState *newState);

    void flushTlbCache();

    void flushTlbCachePage(klee::ObjectState *objectState, int mmu_idx, int index);

    void updateTlbEntryConcreteStatus(struct CPUX86State* env,
                                      unsigned mmu_idx, unsigned index,
                                      const klee::ObjectState *state);

    #if defined(SE_ENABLE_PHYSRAM_TLB)
    void updateRamTlb(const klee::MemoryObject *mo,
                      const klee::ObjectState *oldState,
                      klee::ObjectState *newState);
    void clearRamTlb();
    #endif

    void clearTlbOwnership();

    void updateTlbEntry(struct CPUX86State* env,
                        int mmu_idx, uint64_t virtAddr, uint64_t hostAddr);

    bool audit();
};

}

#endif
