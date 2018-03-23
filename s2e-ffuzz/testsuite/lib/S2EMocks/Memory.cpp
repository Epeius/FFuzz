extern "C" {
#include <cpu.h>
#include <s2e/s2e_config.h>
}


#include <s2e/AddressSpaceCache.h>
#include <klee/ExecutionState.h>

#include <testsuite/Memory.h>

using namespace klee;

namespace s2e {
namespace test {

MemoryMock* MemoryMock::Get(ExecutionState *state, uintptr_t hostAddressBase, uintptr_t pageCount)
{
    MemoryMock *m = new MemoryMock(pageCount);
    m->InitMemorySpace(state, hostAddressBase);
    return m;
}

void MemoryMock::InitMemorySpace(ExecutionState *state, uintptr_t hostAddressBase)
{
    for (unsigned i = 0; i < m_pageCount; ++i) {
        MemoryObject *mo = new MemoryObject(hostAddressBase + i * TARGET_PAGE_SIZE, TARGET_PAGE_SIZE, false, true, false, NULL);
        mo->doNotifyOnConcretenessChange = true;
        mo->isUserSpecified = true;
        mo->isSplittable = true;
        mo->isMemoryPage = true;
        ObjectState *os = new ObjectState(mo);
        state->addressSpace.bindObject(mo, os);
        m_memoryObjects.push_back(mo);
        m_objectStates.push_back(os);
    }

    m_dirtyMask = new MemoryObject(DIRTY_MASK_ADDRESS, m_pageCount,
                                      false, true, false, NULL);

    state->addressSpace.bindObject(m_dirtyMask, new ObjectState(m_dirtyMask));
}

CPUTLBEntry *MemoryMock::MapTlbEntry(CPUX86State *env, ExecutionState *state,
                                     uintptr_t guestAddress, uintptr_t hostAddress)
{
    assert((guestAddress & ~TARGET_PAGE_MASK) == 0);
    assert((hostAddress & ~TARGET_PAGE_MASK) == 0);
    unsigned mmu_idx = 0;
    unsigned index = (guestAddress >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    CPUTLBEntry *te = &env->tlb_table[mmu_idx][index];

    ObjectPair op = state->addressSpace.findObject(hostAddress);
    assert(op.first && op.second);

    uintptr_t addend = (uintptr_t) op.first->address;
    te->addend = addend - hostAddress;
    te->addr_read = guestAddress;
    te->addr_write = guestAddress;
    te->addr_code = guestAddress;
    return te;
}

CPUTLBEntry *MemoryMock::GetTlbEntry(CPUX86State *env, uintptr_t guestAddress) const
{
    unsigned mmu_idx = 0;
    unsigned index = (guestAddress >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    return &env->tlb_table[mmu_idx][index];
}

}
}
