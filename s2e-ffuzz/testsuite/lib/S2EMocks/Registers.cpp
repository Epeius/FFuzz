extern "C" {
#include <cpu.h>
#include <s2e/s2e_config.h>
}


#include <s2e/AddressSpaceCache.h>
#include <klee/ExecutionState.h>

#include <testsuite/Registers.h>

using namespace klee;

namespace s2e {
namespace test {

void RegistersMock::Initialize(ExecutionState *state, void *env,
                S2EExecutionStateRegisters &registers)
{
    m_symbolicRegs = new MemoryObject((uintptr_t) env, offsetof(CPUX86State, eip),
                                      false, true, false, NULL);

    state->addressSpace.bindObject(m_symbolicRegs, new ObjectState(m_symbolicRegs));

    m_concreteRegs = new MemoryObject((uintptr_t) env + offsetof(CPUX86State, eip),
                                      sizeof(CPUX86State) - offsetof(CPUX86State, eip),
                                      false, true, false, NULL);
    state->addressSpace.bindObject(m_concreteRegs, new ObjectState(m_concreteRegs));

    registers.initialize(state->addressSpace, m_symbolicRegs, m_concreteRegs);
}

RegistersMock *RegistersMock::Get(ExecutionState *state, void *env,
                          S2EExecutionStateRegisters &registers)
{
    RegistersMock *ret = new RegistersMock();
    ret->Initialize(state, env, registers);
    return ret;
}

}
}
