///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_AntiDebuggingDetector_H
#define S2E_PLUGINS_AntiDebuggingDetector_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitor.h>

namespace s2e {
namespace plugins {

class AntiDebuggingDetector : public Plugin
{
    S2E_PLUGIN
public:
    AntiDebuggingDetector(S2E* s2e): Plugin(s2e) {}

    void initialize();



private:
    ModuleExecutionDetector *m_detector;
    OSMonitor *m_monitor;

    sigc::connection m_onTranslateInstructionEndConnection;
    sigc::connection m_onTranslateBlockCompleteConnection;
    sigc::connection m_onModuleTranslateBlockStartConnection;


    void onTranslateBlockStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateBlockComplete(
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t endPc);


    void onModuleTranslateBlockStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            const ModuleDescriptor &module,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateInstructionEnd(
            ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc, enum special_instruction_t type
            );

    void onModuleTranslateBlockComplete(
            S2EExecutionState* state,
            const ModuleDescriptor &desc, TranslationBlock *tb,
            uint64_t endPc);

    void onInstruction(S2EExecutionState *state, uint64_t pc);

    void onProcessUnload(
        S2EExecutionState* state, uint64_t pageDir, uint64_t pid);
};

class AntiDebuggingDetectorState:public PluginState
{
private:
    klee::ref<klee::Expr> m_lastTsc;
    uint64_t m_pid;

public:

    AntiDebuggingDetectorState();
    virtual ~AntiDebuggingDetectorState();
    virtual AntiDebuggingDetectorState* clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    klee::ref<klee::Expr> getNextTsc(S2EExecutionState *state);

    friend class AntiDebuggingDetector;
};


} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_AntiDebuggingDetector_H
