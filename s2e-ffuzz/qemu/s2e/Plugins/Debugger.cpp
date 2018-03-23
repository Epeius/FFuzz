///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/cpu.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <sstream>

#include "Debugger.h"

namespace s2e {
namespace plugins {


S2E_DEFINE_PLUGIN(Debugger, "Debugger plugin", "",);

void Debugger::initialize()
{
    assert(false && "Need to implement onConcreteDataMemoryAccess");
    m_dataTriggers = NULL;
    m_dataTriggerCount = 0;

    //Catch all accesses to the stack
    m_monitorStack = s2e()->getConfig()->getBool(getConfigKey() + ".monitorStack");

    //Catch accesses that are above the specified address
    m_catchAbove = s2e()->getConfig()->getInt(getConfigKey() + ".catchAccessesAbove");

    //Start monitoring after the specified number of seconds
    m_timeTrigger = s2e()->getConfig()->getInt(getConfigKey() + ".timeTrigger");
    m_elapsedTics = 0;

    //Manual addresses
    //XXX: Note that stack monitoring and manual addresses cannot be used together...
    initList(getConfigKey() + ".dataTriggers", &m_dataTriggers, &m_dataTriggerCount);
    initAddressTriggers(getConfigKey() + ".addressTriggers");

    if (!m_timeTrigger) {
        s2e()->getCorePlugin()->onAfterSymbolicDataMemoryAccess.connect(
                sigc::mem_fun(*this, &Debugger::onAfterSymbolicDataMemoryAccess));
    }else {
        m_timerConnection = s2e()->getCorePlugin()->onTimer.connect(
                sigc::mem_fun(*this, &Debugger::onTimer));
    }


}

void Debugger::initList(const std::string &key, uint64_t **ptr, unsigned *size)
{
    ConfigFile::integer_list list;

    list = s2e()->getConfig()->getIntegerList(key);
    *size = list.size();

    if (list.size() > 0) {
        *ptr = new uint64_t[list.size()];
        ConfigFile::integer_list::iterator it;
        unsigned i=0;

        for (it = list.begin(); it != list.end(); ++it) {
            getInfoStream() << "Adding trigger for value " << hexval(*it) << '\n';
            (*ptr)[i] = *it;
            ++i;
        }
    }
}

void Debugger::initAddressTriggers(const std::string &key)
{
    ConfigFile *cfg = s2e()->getConfig();

    unsigned i=0;
    do {
        ++i; //Indices in LUA start with 1.
        std::stringstream ss;
        ConfigFile::integer_list list;
        bool ok;

        ss << key << "[" << (i) << "]";
        getDebugStream() << __FUNCTION__ << ": scanning " << ss.str() << '\n';
        list = cfg->getIntegerList(ss.str(), ConfigFile::integer_list(), &ok);
        if (!ok) {
            return;
        }

        if (list.size() == 0) {
            continue;
        }

        uint64_t e=0,s=0;

        if (list.size() >= 1)
            s = list[0];

        if (list.size() >= 2)
            e = list[1];
        else
            e = s;

        if (e < s) {
            getWarningsStream() << hexval(e) << " must be bigger than " << s << '\n';
            continue;
        }
        m_addressTriggers.push_back(AddressRange(list[0], list[1]));
    }while(true);
}

Debugger::~Debugger(void)
{
    if (m_dataTriggers) {
        delete [] m_dataTriggers;
    }
}

bool Debugger::dataTriggered(uint64_t data) const
{
    for (unsigned i=0; i<m_dataTriggerCount; ++i) {
        if (m_dataTriggers[i] == data) {
            return true;
        }
    }
    return false;
}

bool Debugger::addressTriggered(uint64_t address) const
{
    for (unsigned i=0; i<m_addressTriggers.size(); ++i) {
        if (m_addressTriggers[i].start <= address &&
            m_addressTriggers[i].end >= address ) {
            return true;
        }
    }
    return false;
}

bool Debugger::decideTracing(S2EExecutionState *state, uint64_t addr, uint64_t data) const
{
    if (m_monitorStack) {
        //Assume that the stack is 8k and 8k-aligned
        if ((state->getSp() & ~0x3FFFF) == (addr & ~0x3FFFF)) {
            return true;
        }
    }

    if (dataTriggered(data)) {
        return true;
    }

    if (addressTriggered(addr)) {
        return true;
    }

    return false;
}

void Debugger::onAfterSymbolicDataMemoryAccess(S2EExecutionState *state,
                               klee::ref<klee::Expr> address,
                               klee::ref<klee::Expr> hostAddress,
                               klee::ref<klee::Expr> value,
                               unsigned flags)
{
    if(!isa<klee::ConstantExpr>(address) || !isa<klee::ConstantExpr>(value)) {
        //We do not support symbolic values yet...
        return;
    }

    uint64_t addr = cast<klee::ConstantExpr>(address)->getZExtValue(64);
    uint64_t val = cast<klee::ConstantExpr>(value)->getZExtValue(64);

    if (addr < m_catchAbove) {
        //Skip uninteresting ranges
        return;
    }


    if (decideTracing(state, addr, val)) {
        getDebugStream() <<
                   " MEM PC=" << hexval(state->getPc()) <<
                   " Addr=" << hexval(addr) <<
                   " Value=" << hexval(val) <<
                   " IsWrite=" << (flags & MEM_TRACE_FLAG_WRITE) << '\n';
    }

}

void Debugger::onTranslateInstructionStart(
    ExecutionSignal *signal,
    S2EExecutionState *state,
    TranslationBlock *tb,
    uint64_t pc
    )
{
    //signal->connect(sigc::mem_fun(*this, &Debugger::onInstruction));

    /*if (pc <= 0xc02144b1 && pc >= 0xc02142f8) {
        signal->connect(sigc::mem_fun(*this, &Debugger::onInstruction));
    }

    if (pc <= 0xc0204e20 && pc >= 0xc0202e20) {
        signal->connect(sigc::mem_fun(*this, &Debugger::onInstruction));
    }*/

}

void Debugger::onInstruction(S2EExecutionState *state, uint64_t pc)
{
    getDebugStream() << "IT " << hexval(pc) <<
            " CC_SRC=" << state->readCpuRegister(offsetof(CPUX86State, cc_src), klee::Expr::Int32) <<
            '\n';
}

void Debugger::onTimer()
{
    if (m_elapsedTics++ < m_timeTrigger) {
        return;
    }

    getInfoStream() << "Debugger Plugin: Enabling memory tracing" << '\n';
    s2e()->getCorePlugin()->onAfterSymbolicDataMemoryAccess.connect(
            sigc::mem_fun(*this, &Debugger::onAfterSymbolicDataMemoryAccess));

    //s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
      //      sigc::mem_fun(*this, &Debugger::onTranslateInstructionStart));

    s2e()->getCorePlugin()->onTranslateInstructionEnd.connect(
            sigc::mem_fun(*this, &Debugger::onTranslateInstructionStart));

    m_timerConnection.disconnect();
}



} // namespace plugins
} // namespace s2e
