#ifndef S2E_TESTSUITE_MEMORY_MOCK

#define S2E_TESTSUITE_MEMORY_MOCK

#include <klee/Memory.h>
#include <klee/ExecutionState.h>
#include <vector>

#include <s2e/S2EExecutionStateMemory.h>

extern "C" {
struct CPUTLBEntry;
}

namespace s2e {
namespace test {

class MemoryMock {
private:

    const uintptr_t DIRTY_MASK_ADDRESS = 0xf0000000;
    klee::MemoryObject *m_dirtyMask;
    std::vector<klee::MemoryObject*> m_memoryObjects;
    std::vector<klee::ObjectState*> m_objectStates;

    uintptr_t m_pageCount;


    MemoryMock(uintptr_t pageCount) {
        m_pageCount = pageCount;
    }

    void InitMemorySpace(klee::ExecutionState *state, uintptr_t hostAddressBase);

public:
    static MemoryMock* Get(klee::ExecutionState *state, uintptr_t hostAddressBase, uintptr_t pageCount);
    CPUTLBEntry *MapTlbEntry(CPUX86State *env, klee::ExecutionState *state,
                             uintptr_t guestAddress, uintptr_t hostAddress);

    CPUTLBEntry *GetTlbEntry(CPUX86State *env, uintptr_t guestAddress) const;
    klee::MemoryObject *GetDirtyMask() const {
        return m_dirtyMask;
    }

};

}
}

#endif
