extern "C" {
#include <cpu.h>
#include <s2e/s2e_config.h>
}
#include <iostream>
#include <s2e/AddressSpaceCache.h>
#include <klee/ExecutionState.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using namespace testing;
using namespace klee;
using namespace s2e;

namespace {

class ExecutionStateTest: public ExecutionState {
public:
    AddressSpaceCache *m_asCache;

public:
    ExecutionStateTest(AddressSpaceCache *cache) : ExecutionState(std::vector<ref<Expr> >()),
    m_asCache(cache){}

    virtual void addressSpaceChange(const klee::MemoryObject *mo,
                            const klee::ObjectState *oldState,
                            klee::ObjectState *newState)
    {
        if((oldState && oldState->getBitArraySize() == SE_RAM_OBJECT_SIZE)) {
            m_asCache->invalidate(mo->address);
        }
    }
};

class AddressSpaceCacheTest : public Test {
protected:

    const unsigned PAGE_COUNT = 0x10;
    const unsigned SMALL_OBJECT_COUNT = TARGET_PAGE_SIZE / S2E_RAM_SUBOBJECT_SIZE;

    AddressSpace *m_as;
    AddressSpaceCache *m_cache;
    ExecutionStateTest *m_state;

    MemoryObject **m_mo;
    ObjectState **m_os;

    void InitMemorySpace(ExecutionStateTest *state) {
        m_as = new AddressSpace(m_state);
        m_cache = new AddressSpaceCache(m_as);

        state->m_asCache = m_cache;

        m_mo = new MemoryObject*[PAGE_COUNT];
        m_os = new ObjectState*[PAGE_COUNT];

        for (unsigned i = 0; i < PAGE_COUNT; ++i) {
            m_mo[i] = new MemoryObject(i * TARGET_PAGE_SIZE, TARGET_PAGE_SIZE, false, true, false, NULL);
            m_mo[i]->isUserSpecified = true;
            m_mo[i]->isSplittable = true;
            m_os[i] = new ObjectState(m_mo[i]);
            m_as->bindObject(m_mo[i], m_os[i]);
        }

        m_cache->registerPool(0x0, PAGE_COUNT * TARGET_PAGE_SIZE);
    }

    void Split(uintptr_t address, std::vector<MemoryObject*> &smallMo,
               std::vector<ObjectState*> &smallOs) {

        ObjectPair op = m_cache->get(address);

        const_cast<ObjectState*>(op.second)->initializeConcreteMask();

        for (unsigned i = 0; i < SMALL_OBJECT_COUNT; ++i) {
            MemoryObject *mo = new MemoryObject(address + i * S2E_RAM_SUBOBJECT_SIZE, S2E_RAM_SUBOBJECT_SIZE, false, true, false, NULL);
            mo->isUserSpecified = true;

            ObjectState *os = op.second->split(mo, i * S2E_RAM_SUBOBJECT_SIZE);

            smallMo.push_back(mo);
            smallOs.push_back(os);
        }

        m_cache->notifySplit(op.second, smallOs);

        m_as->unbindObject(op.first);
        for (unsigned i = 0; i < SMALL_OBJECT_COUNT; ++i) {
            m_as->bindObject(smallMo[i], smallOs[i]);
        }
    }

    virtual void SetUp() {
        m_state = new ExecutionStateTest(NULL);
        InitMemorySpace(m_state);
    }

    virtual void TearDown() {
        delete m_cache;
        delete m_as;
        delete m_state;
        delete [] m_os;
        delete [] m_mo;
    }

};


TEST_F(AddressSpaceCacheTest, IterateOverAllPages) {

    for (unsigned i = 0; i < PAGE_COUNT; ++i) {
        ObjectPair op = m_cache->get(i * TARGET_PAGE_SIZE);
        ASSERT_EQ(op.first, m_mo[i]);
        ASSERT_EQ(op.second, m_os[i]);
    }
}

TEST_F(AddressSpaceCacheTest, TestSplit) {

    const unsigned START = 0x3000;
    ObjectPair op = m_cache->get(START);

    std::vector<MemoryObject*> smallMo;
    std::vector<ObjectState*> smallOs;

    Split(START, smallMo, smallOs);

    op = m_cache->get(START);
    ASSERT_EQ(op.first, smallMo[0]);
    ASSERT_EQ(op.second, smallOs[0]);
}

TEST_F(AddressSpaceCacheTest, TestGetBaseObject) {

    const unsigned START = 0x3000;
    ObjectPair op = m_cache->get(START);

    std::vector<MemoryObject*> smallMo;
    std::vector<ObjectState*> smallOs;

    Split(START, smallMo, smallOs);

    ObjectState *baseOs1 = m_cache->getBaseObject(smallOs[3]);

    ASSERT_EQ(baseOs1, smallOs[0]);
}

}
