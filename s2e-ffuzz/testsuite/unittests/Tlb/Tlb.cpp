extern "C" {
#include <cpu.h>
#include <helper.h>
#include <s2e/s2e_config.h>
}
#include <iostream>
#include <string>
#include <s2e/S2EExecutionStateRegisters.h>
#include <s2e/S2EExecutionStateMemory.h>
#include <s2e/S2EExecutionStateTlb.h>
#include <s2e/AddressSpaceCache.h>
#include <klee/ExecutionState.h>
#include <testsuite/Registers.h>
#include <testsuite/Memory.h>

#include <klee/Common.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace testing;
using namespace klee;
using namespace s2e;
using namespace s2e::test;

namespace {
const uint32_t MAGIC = 0xdeadbeef;
const uint32_t SOLVER_MAGIC = 0xbadcafe;
const uint32_t SOLVER_MAGIC_BYTE = 0xfe;
const uint32_t SOLVER_MAGIC_BYTEx4 = 0xfefefefe;
const uint32_t PAGE_COUNT = 10;
const uintptr_t HOST_ADDRESS_BASE = 0xABC000;
}

#define OFFSET(struc, field) ((uintptr_t)(&((struc*)0)->field))

extern "C" {
int g_s2e_single_path_mode = false;

void s2e_read_register_concrete(unsigned offset, uint8_t* buf, unsigned size)
{
    assert(false);
}

void s2e_write_register_concrete(unsigned offset, uint8_t* buf, unsigned size)
{
    assert(false);
}

uintptr_t se_get_host_address(target_phys_addr_t paddr)
{
    if (paddr >= HOST_ADDRESS_BASE + PAGE_COUNT * TARGET_PAGE_SIZE) {
        return 0;
    }

    return paddr + HOST_ADDRESS_BASE;
}

target_phys_addr_t cpu_get_phys_page_debug(CPUX86State *env, target_ulong addr)
{
    if (addr >= PAGE_COUNT * TARGET_PAGE_SIZE) {
        return -1;
    }

    return addr;
}

int g_s2e_fast_concrete_invocation = 1;
CPUX86State *env;
uint32_t cpu_cc_compute_all(CPUX86State *env1, int op) {
    return MAGIC;
}

}

namespace {

class ExecutionStateTest;

class S2EExecutionStateRegistersTest : public S2EExecutionStateRegisters {
    friend class ExecutionStateTest;

public:
    S2EExecutionStateRegistersTest(const bool *active, const bool *running_concrete,
              klee::IAddressSpaceNotification *notification,
              klee::IConcretizer *concretizer) :
    S2EExecutionStateRegisters(active, running_concrete, notification, concretizer) {};

    static void reset() {
        s_concreteRegs = NULL;
        s_symbolicRegs = NULL;
    }
};

class S2EExecutionStateMemoryTest : public S2EExecutionStateMemory {
    friend class ExecutionStateTest;

public:
    static void reset() {
        s_dirtyMask = NULL;
    }
};

class ExecutionStateTest: public ExecutionState, public IConcretizer {
public:
    S2EExecutionStateRegistersTest m_registers;
    AddressSpaceCache m_asCache;
    S2EExecutionStateTlb m_tlb;
    S2EExecutionStateMemoryTest m_memory;

    bool m_active;
    bool m_runningConcrete;
    bool m_lastBecameConcrete;
    bool m_symbStatusChanged;

public:
    ExecutionStateTest() : ExecutionState(std::vector<ref<Expr> >()),
    m_registers(&m_active, &m_runningConcrete, this, this),
    m_asCache(&addressSpace), m_tlb(&m_asCache, &m_registers),
    m_active(true), m_runningConcrete(false), m_lastBecameConcrete(false),
    m_symbStatusChanged(false){

    }

    virtual void addressSpaceChange(const klee::MemoryObject *mo,
                            const klee::ObjectState *oldState,
                            klee::ObjectState *newState)
    {
        if (oldState && mo->isMemoryPage) {
            if ((mo->address & ~SE_RAM_OBJECT_MASK) == 0) {
                m_asCache.invalidate(mo->address & SE_RAM_OBJECT_MASK);
                m_tlb.addressSpaceChangeUpdateTlb(mo, oldState, newState);
                return;
            }
        }

        m_registers.addressSpaceChange(mo, oldState, newState);
    }

    //We don't care about concrete values here
    virtual uint64_t concretize(ref<Expr> e, const std::string &reason, bool silent) {
        return SOLVER_MAGIC & ((1ll << e->getWidth()) - 1);
    }

    virtual void addressSpaceSymbolicStatusChange(ObjectState *object, bool becameConcrete) {
        EXPECT_EQ(object->getBitArraySize(), (unsigned) SE_RAM_OBJECT_SIZE);

        m_lastBecameConcrete = becameConcrete;
        m_symbStatusChanged = true;

        object = m_asCache.getBaseObject(object);
        m_tlb.updateTlb(object->getObject(), object, object);
    }

    virtual ExecutionState* clone() {
        m_tlb.clearTlbOwnership();

        ExecutionStateTest *ret = new ExecutionStateTest(*this);
        ret->addressSpace.state = ret;
        ret->m_registers.update(ret->addressSpace, &ret->m_active, &ret->m_runningConcrete, ret, ret);
        ret->m_tlb.assignNewState(&ret->m_asCache, &ret->m_registers);
        m_registers.update(addressSpace, &m_active, &m_runningConcrete, this, this);
        m_memory.update(&addressSpace, &m_asCache, &m_active, this, this);
        return ret;
    }

    ref<Expr> createSymbolicValue(const char *name, unsigned size) {
        const Array *array = new Array(name, size);

        MemoryObject *mo = new MemoryObject(0, size, false, false, false, NULL);
        mo->setName(name);

        symbolics.push_back(std::make_pair(mo, array));
        return  Expr::createTempRead(array, size * 8);
    }
};

class ExecutorMock {
public:
    static ExecutionStateTest *Fork(ExecutionStateTest *state) {
        state->m_tlb.clearTlbOwnership();
        ExecutionStateTest *newState = static_cast<ExecutionStateTest*>(state->branch());
        newState->m_registers.saveConcreteState();
        newState->m_tlb.clearTlbOwnership();
        newState->m_active = false;
        return newState;
    }

    static void SwitchState(ExecutionStateTest *oldState, ExecutionStateTest *newState) {
        if (oldState->m_runningConcrete) {
            oldState->m_registers.copySymbRegs(false);
            oldState->m_runningConcrete = false;
        }

        oldState->m_registers.saveConcreteState();
        oldState->m_active = false;

        newState->m_registers.restoreConcreteState();
        newState->m_active = true;
    }
};

class TlbTest : public Test {
protected:

    ExecutionStateTest *m_state;
    RegistersMock *m_regs;
    MemoryMock *m_mem;
    CPUX86State m_env;

    virtual void SetUp() {
        memset(&m_env, 0, sizeof(m_env));
        env = &m_env;

        if (!Context::initialized()) {
            Context::initialize(true, Expr::Int64);
        }

        m_state = new ExecutionStateTest();
        m_state->m_registers.reset();
        m_state->m_memory.reset();
        m_regs = RegistersMock::Get(m_state, &m_env, m_state->m_registers);
        m_mem = MemoryMock::Get(m_state, HOST_ADDRESS_BASE, PAGE_COUNT);
        m_state->m_memory.initialize(&m_state->addressSpace, &m_state->m_asCache,
                                     &m_state->m_active,
                                     m_state, m_state, m_mem->GetDirtyMask());
        m_state->m_active = true;

    }

    virtual void TearDown() {
        delete m_state;
    }

    void MapS2ETLBEntry(ExecutionState *state, uintptr_t hostAddr, uintptr_t virtAddr) {
        int mmu_idx = 0;

        CPUTLBEntry *te = m_mem->MapTlbEntry(&m_env, m_state, virtAddr, hostAddr);
        m_state->m_tlb.updateTlbEntry(&m_env, mmu_idx, virtAddr, hostAddr);

        EXPECT_FALSE(te->addr_code & TLB_NOT_OURS);
        EXPECT_FALSE(te->addr_read & TLB_NOT_OURS);
        EXPECT_FALSE(te->addr_write & TLB_NOT_OURS);

        EXPECT_FALSE(te->addr_code & TLB_SYMB);
        EXPECT_FALSE(te->addr_read & TLB_SYMB);
        EXPECT_FALSE(te->addr_write & TLB_SYMB);

        ObjectPair op = m_state->addressSpace.findObject(hostAddr);

        uintptr_t buf = (uintptr_t) op.second->getConcreteStore();
        uintptr_t addend = buf - virtAddr;
        EXPECT_EQ(addend, te->se_addend);
    }

    void MapAllEntries() {
        for (unsigned i = 0; i < PAGE_COUNT; ++i) {
            uintptr_t address = HOST_ADDRESS_BASE + i * TARGET_PAGE_SIZE;
            MapS2ETLBEntry(m_state, address, i * TARGET_PAGE_SIZE);

            ObjectPair op = m_state->addressSpace.findObject(address);
            EXPECT_TRUE(op.first->doNotifyOnConcretenessChange);
        }
    }
};


TEST_F(TlbTest, MapAllTlbEntries)
{
    MapAllEntries();
}

TEST_F(TlbTest, CopyOnWrite)
{
    MapAllEntries();

    CPUTLBEntry *te = m_mem->GetTlbEntry(&m_env, 0);
    EXPECT_FALSE(te->addr_write & TLB_NOT_OURS);

    ObjectPair op = m_state->addressSpace.findObject((uintptr_t) HOST_ADDRESS_BASE + 0);
    EXPECT_EQ(te->objectState, op.second);

    ExecutionStateTest *newState = ExecutorMock::Fork(m_state);
    ExecutorMock::SwitchState(m_state, newState);

    EXPECT_EQ(te->objectState, op.second);

    op = newState->addressSpace.findObject((uintptr_t) HOST_ADDRESS_BASE + 0);

    EXPECT_TRUE(te->addr_write & TLB_NOT_OURS);

    ObjectState *obj = newState->addressSpace.getWriteable(op.first, op.second);
    EXPECT_FALSE(te->addr_write & TLB_NOT_OURS);
    EXPECT_EQ(te->objectState, obj);
}


TEST_F(TlbTest, Flush)
{
    MapAllEntries();

    uintptr_t address = TARGET_PAGE_SIZE;
    CPUTLBEntry *te = m_mem->GetTlbEntry(&m_env, address);
    EXPECT_NE(0ull, te->se_addend);
    EXPECT_NE((void*) NULL, te->objectState);


    ObjectPair op = m_state->addressSpace.findObject((uintptr_t) se_get_host_address(address));
    unsigned index = (address >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    m_state->m_tlb.flushTlbCachePage(const_cast<ObjectState*>(op.second), 0, index);


    EXPECT_EQ(0ull, te->se_addend);
    EXPECT_EQ((void*) NULL, te->objectState);

}

TEST_F(TlbTest, ReadWriteMemory8SymbolicData)
{
    MapAllEntries();

    const unsigned address = 0x123;

    /* Write a symbolic value */
    ref<Expr> val = m_state->createSymbolicValue("mem", 1);
    bool ret = m_state->m_memory.writeMemory8(address, val);
    EXPECT_TRUE(ret);

    /* Check that symbolicness change has been notified */
    EXPECT_TRUE(m_state->m_symbStatusChanged);
    EXPECT_FALSE(m_state->m_lastBecameConcrete);

    CPUTLBEntry *te = m_mem->GetTlbEntry(&m_env, address);
    EXPECT_TRUE(te->addr_read & TLB_SYMB);
    EXPECT_TRUE(te->addr_write & TLB_SYMB);
    EXPECT_TRUE(te->addr_code & TLB_SYMB);

    /* Check that we can read back the original value */
    ref<Expr> readVal = m_state->m_memory.readMemory8(address);
    EXPECT_EQ(val, readVal);
}

TEST_F(TlbTest, ReadWriteSymbolicWithConcreteData32)
{
    MapAllEntries();

    const unsigned address = 0x123;
    ref<Expr> writtenValue = ref<Expr>(ConstantExpr::create(MAGIC, Expr::Int32));
    bool writeStatus = m_state->m_memory.writeMemory(address, writtenValue);
    EXPECT_TRUE(writeStatus);

    ref<Expr> readValue = m_state->m_memory.readMemory(address, Expr::Int32);
    EXPECT_EQ(writtenValue, readValue);
}

TEST_F(TlbTest, ReadWriteSymbolicWithSymbolicData32)
{
    MapAllEntries();

    const unsigned address = 0x123;
    ref<Expr> writtenValue = m_state->createSymbolicValue("mem", 4);
    bool writeStatus = m_state->m_memory.writeMemory(address, writtenValue);
    EXPECT_TRUE(writeStatus);

    ref<Expr> readValue = m_state->m_memory.readMemory(address, Expr::Int32);
    EXPECT_EQ(writtenValue, readValue);
}

TEST_F(TlbTest, WriteSymbolicDataReadConcrete)
{
    MapAllEntries();

    const unsigned address = 0x123;
    ref<Expr> writtenValue = m_state->createSymbolicValue("mem", 4);
    bool writeStatus = m_state->m_memory.writeMemory(address, writtenValue);
    EXPECT_TRUE(writeStatus);

    /* Read back a concretized value */
    uint32_t readValue;
    bool readStatus = m_state->m_memory.readMemoryConcrete(address, &readValue, sizeof(readValue));
    EXPECT_TRUE(readStatus);

    EXPECT_EQ(SOLVER_MAGIC_BYTEx4, readValue);

    /* Read again to make sure that concretization worked */
    ref<Expr> symbValue = m_state->m_memory.readMemory(address, Expr::Int32);
    EXPECT_EQ(ref<Expr>(ConstantExpr::create(SOLVER_MAGIC_BYTEx4, Expr::Int32)), symbValue);
}


TEST_F(TlbTest, ReadWriteMemoryConcreteOverlappedPage)
{
    MapAllEntries();

    const unsigned address = TARGET_PAGE_SIZE - 1;
    uint64_t writtenValue = MAGIC;
    bool writeStatus = m_state->m_memory.writeMemoryConcrete(address, &writtenValue, sizeof(writtenValue));
    EXPECT_TRUE(writeStatus);

    /* Check that symbolicness change has not changed */
    EXPECT_FALSE(m_state->m_symbStatusChanged);

    uint64_t readValue;
    bool readStatus = m_state->m_memory.readMemoryConcrete(address, &readValue, sizeof(readValue));
    EXPECT_TRUE(readStatus);

    EXPECT_EQ(writtenValue, readValue);
}


TEST_F(TlbTest, TransferRamConcreteOverlappedPage)
{
    MapAllEntries();

    const unsigned address = TARGET_PAGE_SIZE - 1;
    uintptr_t hostAddress = se_get_host_address(address);
    uint64_t writtenValue = MAGIC;

    m_state->m_memory.transferRam(NULL, hostAddress, &writtenValue, sizeof(writtenValue), true, false, false);

    /* Check that symbolicness change has not changed */
    EXPECT_FALSE(m_state->m_symbStatusChanged);

    uint64_t readValue;
    m_state->m_memory.transferRam(NULL, hostAddress, &readValue, sizeof(readValue), false, false, false);

    EXPECT_EQ(writtenValue, readValue);
}

TEST_F(TlbTest, WriteSymbolicByteReadWithConcretization)
{
    MapAllEntries();

    const unsigned address = 0x123;
    ref<Expr> writtenValue = m_state->createSymbolicValue("mem", 1);
    bool writeStatus = m_state->m_memory.writeMemory(address, writtenValue);
    EXPECT_TRUE(writeStatus);

    uint8_t byte;
    bool b = m_state->m_memory.readMemoryConcrete8(address, &byte, VirtualAddress, true);
    EXPECT_TRUE(b);
    EXPECT_EQ(SOLVER_MAGIC_BYTE, byte);

    /* Since we added a constraint, the memory should contain the concrete value */
    ref<Expr> readValue = m_state->m_memory.readMemory(address, Expr::Int8);
    EXPECT_EQ(ref<Expr>(ConstantExpr::create(SOLVER_MAGIC_BYTE, Expr::Int8)), readValue);
}

TEST_F(TlbTest, WriteSymbolicByteReadWithoutConcretization)
{
    MapAllEntries();

    const unsigned address = 0x123;
    ref<Expr> writtenValue = m_state->createSymbolicValue("mem", 1);
    bool writeStatus = m_state->m_memory.writeMemory(address, writtenValue);
    EXPECT_TRUE(writeStatus);

    uint8_t byte;
    bool b = m_state->m_memory.readMemoryConcrete8(address, &byte, VirtualAddress, false);
    EXPECT_TRUE(b);
    EXPECT_EQ(SOLVER_MAGIC_BYTE, byte);

    /* No constraint, no overwrite */
    ref<Expr> readValue = m_state->m_memory.readMemory(address, Expr::Int8);
    EXPECT_EQ(writtenValue, readValue);
}


TEST_F(TlbTest, ReadString)
{
    MapAllEntries();

    std::string writtenString = "my fancy string";
    const unsigned address = 0x123;

    bool ret = m_state->m_memory.writeMemoryConcrete(address, writtenString.c_str(), writtenString.size() + 1);
    EXPECT_TRUE(ret);

    std::string readString;
    ret = m_state->m_memory.readString(address, readString);
    EXPECT_TRUE(ret);

    EXPECT_EQ(writtenString, readString);
}

TEST_F(TlbTest, ReadUnicodeString)
{
    MapAllEntries();

    std::string writtenString = "my fancy string";
    const unsigned address = 0x123;

    for (unsigned i = 0; i < writtenString.length(); ++i) {
        uint16_t b = writtenString[i];
        bool ret = m_state->m_memory.writeMemoryConcrete(address + i * sizeof(b), &b, sizeof(b));
        EXPECT_TRUE(ret);
    }


    std::string readString;
    bool ret = m_state->m_memory.readUnicodeString(address, readString);
    EXPECT_TRUE(ret);

    EXPECT_EQ(writtenString, readString);
}

//Check that an invalid host address results in a failed memory access
TEST_F(TlbTest, InvalidHostAddress)
{
    MapAllEntries();

    uintptr_t address = HOST_ADDRESS_BASE + PAGE_COUNT * TARGET_PAGE_SIZE + 0x1234;

    //Write concrete data
    uint64_t value;
    bool status = m_state->m_memory.writeMemoryConcrete(address, &value, sizeof(value), PhysicalAddress);
    EXPECT_FALSE(status);

    //Write symbolic data
    ref<Expr> symbolicValue = m_state->createSymbolicValue("mem", 1);
    status = m_state->m_memory.writeMemory(address, symbolicValue);
    EXPECT_FALSE(status);

    //Read concrete data
    status = m_state->m_memory.readMemoryConcrete(address, &value, sizeof(value), PhysicalAddress);
    EXPECT_FALSE(status);

    symbolicValue = m_state->m_memory.readMemory8(address, PhysicalAddress);
    EXPECT_EQ(NULL, symbolicValue.get());

    uint8_t byte;
    status = m_state->m_memory.readMemoryConcrete8(address, &byte, PhysicalAddress);
    EXPECT_FALSE(status);

}


TEST_F(TlbTest, SplitMemoryPage)
{
    MapAllEntries();

    std::vector<klee::ref<klee::Expr> > testData;

    //Write test data
    for (unsigned i = 0; i < TARGET_PAGE_SIZE; ++i) {
        if (i % 2) {
            std::stringstream ss;
            ss << "data" << i;
            testData.push_back(m_state->createSymbolicValue(ss.str().c_str(), 1));
        } else {
            testData.push_back(klee::ConstantExpr::create(i % S2E_RAM_SUBOBJECT_SIZE, klee::Expr::Int8));
        }

        m_state->m_memory.writeMemory(i, testData[i]);
    }

    //Split the page
    uintptr_t address = HOST_ADDRESS_BASE;
    ObjectPair op = m_state->addressSpace.findObject(address);
    ResolutionList rl;
    bool result = m_state->addressSpace.splitMemoryObject(*m_state, op.first, rl);
    EXPECT_TRUE(result);

    EXPECT_EQ((unsigned) SE_RAM_OBJECT_SIZE / S2E_RAM_SUBOBJECT_SIZE, (unsigned) rl.size());

    //Check if the data is still there
    uintptr_t objectAddress = address;
    for (unsigned i = 0; i < rl.size(); ++i) {
        const MemoryObject *mo = rl[i].first;
        const ObjectState *os = rl[i].second;
        ASSERT_EQ((unsigned) S2E_RAM_SUBOBJECT_SIZE, mo->size);
        ASSERT_EQ(objectAddress, mo->address);
        ASSERT_TRUE(m_state->addressSpace.isOwnedByUs(os));

        for (unsigned j = 0; j < mo->size; ++j) {
            klee::ref<klee::Expr> result = os->read(j, klee::Expr::Int8);
            ASSERT_EQ(testData[i * S2E_RAM_SUBOBJECT_SIZE + j], result);
        }

        objectAddress += S2E_RAM_SUBOBJECT_SIZE;
    }

    //Fork a state
    ExecutionStateTest *newState = ExecutorMock::Fork(m_state);
    op = newState->addressSpace.findObject(address);
    ObjectState *wos = newState->addressSpace.getWriteable(op.first, op.second);

    //Check if the data is still there
    for (unsigned i = 0; i < TARGET_PAGE_SIZE; ++i) {
        klee::ref<klee::Expr> result = newState->m_memory.readMemory(i, klee::Expr::Int8);
        ASSERT_EQ(testData[i], result);
    }
}

}
