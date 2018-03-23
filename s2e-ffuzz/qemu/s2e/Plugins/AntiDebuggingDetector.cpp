///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include "AntiDebuggingDetector.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(AntiDebuggingDetector, "AntiDebuggingDetector S2E plugin", "", "ModuleExecutionDetector");

void AntiDebuggingDetector::initialize()
{
    m_detector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));
    m_monitor = static_cast<OSMonitor*>(s2e()->getPlugin("Interceptor"));


    m_onModuleTranslateBlockStartConnection = m_detector->onModuleTranslateBlockStart.connect(
        sigc::mem_fun(*this,
                      &AntiDebuggingDetector::onModuleTranslateBlockStart)
    );

#if 0
    m_detector->onModuleTranslateBlockComplete.connect(
                sigc::mem_fun(*this, &AntiDebuggingDetector::onModuleTranslateBlockComplete));
#endif


    m_monitor->onProcessUnload.connect(
                sigc::mem_fun(*this, &AntiDebuggingDetector::onProcessUnload));
}

void AntiDebuggingDetector::onProcessUnload(
    S2EExecutionState* state, uint64_t pageDir, uint64_t pid)
{
    DECLARE_PLUGINSTATE(AntiDebuggingDetectorState, state);

    if (pid == plgState->m_pid) {
        g_s2e->getExecutor()->terminateStateEarly(*state, "Process terminated");
    }
}

/////////////////////////////////////////////////

void AntiDebuggingDetector::onTranslateBlockStart(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        TranslationBlock *tb,
        uint64_t pc)
{
    m_onTranslateInstructionEndConnection.disconnect();
    m_onTranslateBlockCompleteConnection.disconnect();

    DECLARE_PLUGINSTATE(AntiDebuggingDetectorState, state);
    if (plgState->m_pid != state->getPageDir()) {
        return;
    }

    /*if (pc >= 0x8000000000000000) {
        return;
    }*/
    if (pc >= 0x80000000) {
        return;
    }

    //getDebugStream(state) << "Translating " << hexval(pc) << "\n";

    m_onTranslateInstructionEndConnection = s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
        sigc::mem_fun(*this, &AntiDebuggingDetector::onTranslateInstructionEnd)
    );

    m_onTranslateBlockCompleteConnection = s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
                sigc::mem_fun(*this, &AntiDebuggingDetector::onTranslateBlockComplete));

}

void AntiDebuggingDetector::onTranslateBlockComplete(
        S2EExecutionState* state,
        TranslationBlock *tb,
        uint64_t endPc)
{
    m_onTranslateInstructionEndConnection.disconnect();
    m_onTranslateBlockCompleteConnection.disconnect();
}

//////////////////////////////////////////////////

void AntiDebuggingDetector::onModuleTranslateBlockStart(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t pc)
{
    DECLARE_PLUGINSTATE(AntiDebuggingDetectorState, state);
    plgState->m_pid = state->getPageDir();

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this,
                      &AntiDebuggingDetector::onTranslateBlockStart)
    );

    m_onModuleTranslateBlockStartConnection.disconnect();
}



void AntiDebuggingDetector::onTranslateInstructionEnd(
        ExecutionSignal *signal,
        S2EExecutionState *state,
        TranslationBlock *tb,
        uint64_t pc, enum special_instruction_t type
        )
{
    if (type != RDTSC) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &AntiDebuggingDetector::onInstruction));}

void AntiDebuggingDetector::onModuleTranslateBlockComplete(
        S2EExecutionState* state,
        const ModuleDescriptor &desc, TranslationBlock *tb,
        uint64_t endPc)
{
    m_onTranslateInstructionEndConnection.disconnect();
}

void AntiDebuggingDetector::onInstruction(S2EExecutionState *state, uint64_t pc)
{
    state->jumpToSymbolicCpp();

    getDebugStream(state) << "Detected rdtsc at " << hexval(pc) << "\n";

    DECLARE_PLUGINSTATE(AntiDebuggingDetectorState, state);

    klee::ref<klee::Expr> symbTime = plgState->getNextTsc(state);
    klee::ref<klee::Expr> high = klee::ExtractExpr::create(symbTime, 32, klee::Expr::Int32);
    state->regs()->write(CPU_OFFSET(regs[R_EAX]), klee::ExtractExpr::create(symbTime, 0, klee::Expr::Int32));
    state->regs()->write(CPU_OFFSET(regs[R_EDX]), high);

    state->addConstraint(g_s2e->getExecutor()->getSolver(*state), klee::EqExpr::create(high, klee::ConstantExpr::create(0, klee::Expr::Int32)));
}

AntiDebuggingDetectorState::AntiDebuggingDetectorState()
{
    m_pid = 0;
}

AntiDebuggingDetectorState::~AntiDebuggingDetectorState()
{

}

AntiDebuggingDetectorState* AntiDebuggingDetectorState::clone() const
{
    return new AntiDebuggingDetectorState(*this);
}

PluginState* AntiDebuggingDetectorState::factory(Plugin *p, S2EExecutionState *state)
{
    return new AntiDebuggingDetectorState();
}

klee::ref<klee::Expr> AntiDebuggingDetectorState::getNextTsc(S2EExecutionState *state)
{
    klee::ref<klee::Expr> symbTime = state->createSymbolicValue("rdtsc", klee::Expr::Int64);
    if (!m_lastTsc.isNull()) {
        klee::ref<klee::Expr> constr = klee::UgtExpr::create(symbTime,
                                                             m_lastTsc);
        state->addConstraint(g_s2e->getExecutor()->getSolver(*state), constr);
    }
    m_lastTsc = symbTime;
    return m_lastTsc;
}

} // namespace plugins
} // namespace s2e
