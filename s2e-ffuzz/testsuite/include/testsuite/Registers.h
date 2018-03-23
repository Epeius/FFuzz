#ifndef S2E_TESTSUITE_REGISTERS_MOCK

#define S2E_TESTSUITE_REGISTERS_MOCK

#include <klee/Memory.h>
#include <s2e/S2EExecutionStateRegisters.h>

namespace s2e {
namespace test {

class RegistersMock {
private:
    klee::MemoryObject *m_symbolicRegs;
    klee::MemoryObject *m_concreteRegs;

    void Initialize(klee::ExecutionState *state,
                    void *env,
                    S2EExecutionStateRegisters &registers);

public:
    static RegistersMock *Get(klee::ExecutionState *state, void *env,
                              S2EExecutionStateRegisters &registers);
};

}
}

#endif
