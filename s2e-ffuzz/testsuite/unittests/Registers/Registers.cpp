extern "C" {
#include <cpu.h>
#include <helper.h>
#include <s2e/s2e_config.h>
}
#include <iostream>
#include <s2e/S2EExecutionStateRegisters.h>
#include <klee/ExecutionState.h>
#include <testsuite/Registers.h>

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
}

#define OFFSET(struc, field) ((uintptr_t)(&((struc*)0)->field))

extern "C" {
void s2e_read_register_concrete(unsigned offset, uint8_t* buf, unsigned size)
{
    assert(false);
}

void s2e_write_register_concrete(unsigned offset, uint8_t* buf, unsigned size)
{
    assert(false);
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

class ExecutionStateTest: public ExecutionState, public IConcretizer {
public:
    S2EExecutionStateRegistersTest m_registers;
    bool m_active;
    bool m_runningConcrete;
    bool m_lastBecameConcrete;
    bool m_symbStatusChanged;

public:
    ExecutionStateTest() : ExecutionState(std::vector<ref<Expr> >()),
    m_registers(&m_active, &m_runningConcrete, this, this),
    m_active(true), m_runningConcrete(false), m_lastBecameConcrete(false),
    m_symbStatusChanged(false){

    }

    virtual void addressSpaceChange(const klee::MemoryObject *mo,
                            const klee::ObjectState *oldState,
                            klee::ObjectState *newState)
    {
        m_registers.addressSpaceChange(mo, oldState, newState);
    }

    //We don't care about concrete values here
    virtual uint64_t concretize(ref<Expr> e, const std::string &reason, bool silent) {
        return SOLVER_MAGIC;
    }

    virtual void addressSpaceSymbolicStatusChange(ObjectState *object, bool becameConcrete) {
        m_lastBecameConcrete = becameConcrete;
        m_symbStatusChanged = true;
        EXPECT_EQ(m_registers.m_symbolicRegs, object);
    }

    ref<Expr> createSymbolicValue(const char *name, unsigned size) {
        const Array *array = new Array(name, size);

        MemoryObject *mo = new MemoryObject(0, size, false, false, false, NULL);
        mo->setName(name);

        symbolics.push_back(std::make_pair(mo, array));
        return  Expr::createTempRead(array, size * 8);
    }
};

class RegistersTest : public Test {
protected:
    RegistersMock *m_regsMock;
    ExecutionStateTest *m_state;
    CPUX86State m_env;

    virtual void SetUp() {
        memset(&m_env, 0, sizeof(m_env));
        env = &m_env;

        if (!Context::initialized()) {
            Context::initialize(true, Expr::Int64);
        }

        m_state = new ExecutionStateTest();
        m_state->m_registers.reset();

        m_regsMock = RegistersMock::Get(m_state, &m_env, m_state->m_registers);


    }

    virtual void TearDown() {
        delete m_regsMock;
        delete m_state;
    }
};


TEST_F(RegistersTest, CopyFromNative) {
    m_state->m_runningConcrete = true;
    m_env.regs[R_ECX] = MAGIC;
    m_state->m_registers.copySymbRegs(false);
    ref<Expr> expr = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, regs[R_ECX]), Expr::Int32);
    EXPECT_EQ(ref<Expr>(ConstantExpr::create(MAGIC, Expr::Int32)), expr);
}

TEST_F(RegistersTest, CopyToNative) {
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, regs[R_ECX]),
                                          ConstantExpr::create(MAGIC, Expr::Int32));

    m_state->m_registers.copySymbRegs(true);
    EXPECT_EQ(MAGIC, m_env.regs[R_ECX]);
}

TEST_F(RegistersTest, GetNativeCpuState) {
    CPUX86State *state = m_state->m_registers.getNativeCpuState();
    EXPECT_EQ(&m_env, state);
}

TEST_F(RegistersTest, GetCpuStateOfActiveState) {
    CPUX86State *state = m_state->m_registers.getCpuState();
    EXPECT_EQ(&m_env, state);
}

TEST_F(RegistersTest, GetCpuStateOfInactiveState) {
    m_state->m_active = false;
    CPUX86State *state = m_state->m_registers.getCpuState();
    EXPECT_NE(&m_env, state);
}

TEST_F(RegistersTest, GetSymbolicMaskOnConcreteCpu) {
    uint64_t mask = m_state->m_registers.getSymbolicRegistersMask();
    EXPECT_EQ(0ull, mask);
}

#define TEST_SYMB_MASK(reg, mask) \
TEST_F(RegistersTest, GetSymbolicMaskSymbolic ## reg) { \
    ref<Expr> symb = m_state->createSymbolicValue(#reg, sizeof(target_ulong));  \
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, reg), symb);  \
    uint64_t actual_mask = m_state->m_registers.getSymbolicRegistersMask();  \
    uint64_t expected_mask = mask;  \
    EXPECT_EQ(expected_mask, actual_mask);  \
}

TEST_SYMB_MASK(cc_op, _M_CC_OP)
TEST_SYMB_MASK(cc_src, _M_CC_SRC)
TEST_SYMB_MASK(cc_dst, _M_CC_DST)
TEST_SYMB_MASK(cc_tmp, _M_CC_TMP)

TEST_F(RegistersTest, GetSymbolicMaskSymbolicEax) {
    ref<Expr> symb = m_state->createSymbolicValue("eax", sizeof(target_ulong));
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, regs[R_EAX]), symb);
    uint64_t mask = m_state->m_registers.getSymbolicRegistersMask();
    uint64_t expected_mask =  _M_EAX;
    EXPECT_EQ(expected_mask, mask);
}

TEST_F(RegistersTest, ReadConcreteValueFromSymbolicRegionInConcreteMode) {
    m_state->m_runningConcrete = true;
    m_env.cc_src = MAGIC;

    uint64_t value = 0;
    bool ret = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), &value, sizeof(target_ulong));
    EXPECT_TRUE(ret);
    EXPECT_EQ(MAGIC, value);
}

TEST_F(RegistersTest, ReadConcreteValueFromSymbolicRegionInSymbolicModeMode) {
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, cc_src), ConstantExpr::create(MAGIC, Expr::Int32));

    uint64_t value = 0;
    bool ret = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), &value, sizeof(target_ulong));
    EXPECT_TRUE(ret);
    EXPECT_EQ(MAGIC, value);
}

#define TEST_READ_CONCRETE_SYMBMODE_WITH_CONC(reg) \
TEST_F(RegistersTest, ReadFromSymbolicRegionInSymbolicModeWithConcretization_ ## reg) { \
    ref<Expr> symbval = m_state->createSymbolicValue(#reg, sizeof(target_ulong)); \
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, reg), symbval); \
    uint64_t value = 0; \
    bool ret = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, reg), &value, sizeof(target_ulong), true); \
    EXPECT_TRUE(ret); \
    EXPECT_EQ(SOLVER_MAGIC, value); \
}


TEST_READ_CONCRETE_SYMBMODE_WITH_CONC(cc_src);
TEST_READ_CONCRETE_SYMBMODE_WITH_CONC(cc_dst);
TEST_READ_CONCRETE_SYMBMODE_WITH_CONC(cc_tmp);
TEST_READ_CONCRETE_SYMBMODE_WITH_CONC(cc_op);

TEST_F(RegistersTest, ReadFromSymbolicRegionInSymbolicModeWithConcretizationGeneralPurpose) {

    for (unsigned i = 0; i < 8; ++i) {
        ref<Expr> symbval = m_state->createSymbolicValue("gpreg", sizeof(target_ulong));
        m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, regs[i]), symbval);
        EXPECT_TRUE(m_state->m_symbStatusChanged);
        EXPECT_FALSE(m_state->m_lastBecameConcrete);
        m_state->m_symbStatusChanged = false;
        m_state->m_lastBecameConcrete = false;

        uint64_t value = 0;
        bool ret = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, regs[i]), &value, sizeof(target_ulong), true);
        EXPECT_TRUE(ret);
        EXPECT_EQ(SOLVER_MAGIC, value);
        EXPECT_TRUE(m_state->m_symbStatusChanged);
        EXPECT_TRUE(m_state->m_lastBecameConcrete);
        m_state->m_symbStatusChanged = false;
        m_state->m_lastBecameConcrete = false;
    }
}

TEST_F(RegistersTest, WriteConcreteDataToSymbolicRegionInConcreteMode) {
    m_state->m_runningConcrete = true;
    target_ulong value = MAGIC;
    m_state->m_registers.write(OFFSET(CPUX86State, cc_src), value);
    EXPECT_EQ(MAGIC, m_env.cc_src);
}

TEST_F(RegistersTest, WriteToSymbolicRegionInSymbolicModeWithStatusChange) {
    //Write a symbolic value to the symbolic region (which is entirely concrete)
    ref<Expr> value = m_state->createSymbolicValue("cc_src", sizeof(target_ulong));
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, cc_src), value);

    //Check that we've got notified that one register became symbolic
    EXPECT_TRUE(m_state->m_symbStatusChanged);
    EXPECT_FALSE(m_state->m_lastBecameConcrete);
    m_state->m_symbStatusChanged = false;
    m_state->m_lastBecameConcrete = false;

    //Write a concrete value to the same register
    uint64_t concValue = MAGIC;
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, cc_src), &concValue, sizeof(target_ulong));

    //Check that we've got notifed that the region became concrete
    EXPECT_TRUE(m_state->m_symbStatusChanged);
    EXPECT_TRUE(m_state->m_lastBecameConcrete);

    //Make sure that we've read back the value that we've just written
    value = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), sizeof(target_ulong) * 8);
    EXPECT_TRUE(isa<ConstantExpr>(value));
    EXPECT_EQ(concValue, dyn_cast<ConstantExpr>(value)->getZExtValue());
}


TEST_F(RegistersTest, WriteConcreteDataToSymbolicRegionInSymbolicModeWithoutStatusChange) {
    ref<Expr> cste = ConstantExpr::create(MAGIC, Expr::Int32);
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, cc_src), cste);

    ref<Expr> readValue = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), Expr::Int32);
    EXPECT_EQ(cste, readValue);
    EXPECT_FALSE(m_state->m_symbStatusChanged);
}

TEST_F(RegistersTest, ReadSymbolicDataFromSymbolicRegionWithoutConcretization) {
    ref<Expr> value = m_state->createSymbolicValue("dummy", sizeof(target_ulong));
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, cc_src), value);

    target_ulong buffer;
    bool b = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), &buffer, sizeof(buffer));
    EXPECT_FALSE(b);
}

TEST_F(RegistersTest, ReadConcreteDataFromSymbolicRegionWithoutConcretization) {
    ref<Expr> cste = ConstantExpr::create(MAGIC, Expr::Int32);
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, cc_src), cste);

    target_ulong buffer;
    bool b = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), &buffer, sizeof(buffer));
    EXPECT_TRUE(b);
    EXPECT_EQ(MAGIC, buffer);
}

TEST_F(RegistersTest, WriteSymbolicDataToSymbolicRegionUnsafe) {
    ref<Expr> value = m_state->createSymbolicValue("dummy", 1);
    m_state->m_registers.writeSymbolicRegionUnsafe(OFFSET(CPUX86State, cc_src), value);

    ref<Expr> readValue = m_state->m_registers.readSymbolicRegion(OFFSET(CPUX86State, cc_src), Expr::Int8);
    EXPECT_EQ(value, readValue);
    EXPECT_TRUE(m_state->m_symbStatusChanged);
    EXPECT_FALSE(m_state->m_lastBecameConcrete);
}


TEST_F(RegistersTest, WriteReadConcreteRegionActiveState) {
    m_state->m_registers.write(OFFSET(CPUX86State, eip), MAGIC);
    uint64_t retval = m_state->m_registers.read<uint64_t>(OFFSET(CPUX86State, eip));
    EXPECT_EQ(MAGIC, retval);
    EXPECT_EQ(MAGIC, m_env.eip);
}


TEST_F(RegistersTest, WriteReadConcreteRegionInactiveState) {
    m_state->m_active = false;
    m_state->m_registers.write(OFFSET(CPUX86State, eip), MAGIC);
    uint64_t retval = m_state->m_registers.read<uint64_t>(OFFSET(CPUX86State, eip));
    EXPECT_EQ(MAGIC, retval);
    EXPECT_EQ(0ull, m_env.eip);
}

TEST_F(RegistersTest, GetPc) {
    m_env.eip = MAGIC;
    uint64_t retval = m_state->m_registers.getPc();
    EXPECT_EQ(MAGIC, retval);
}

TEST_F(RegistersTest, SetPc) {
    m_state->m_registers.setPc(MAGIC);
    EXPECT_EQ(MAGIC, m_env.eip);
}

TEST_F(RegistersTest, GetSetSpConcrete) {
    m_state->m_registers.setSp(MAGIC);
    uint64_t sp = m_state->m_registers.getSp();
    EXPECT_EQ(MAGIC, sp);
}

TEST_F(RegistersTest, GetSetSpSymbolic) {
    ref<Expr> value = m_state->createSymbolicValue("esp", sizeof(target_ulong));
    m_state->m_registers.writeSymbolicRegion(OFFSET(CPUX86State, regs[R_ESP]), value);

    uint64_t sp = m_state->m_registers.getSp();
    EXPECT_EQ(SOLVER_MAGIC, sp);
}

TEST_F(RegistersTest, GetSetPageDir) {
    m_env.cr[3] = MAGIC;
    uint64_t pd = m_state->m_registers.getPageDir();
    EXPECT_EQ(MAGIC, pd);
}

TEST_F(RegistersTest, GetFlags) {
    uint64_t flags = m_state->m_registers.getFlags();
    EXPECT_EQ(MAGIC, flags);
}

}
