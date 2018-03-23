///
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_LuaInstructionAnnotation_H
#define S2E_PLUGINS_LuaInstructionAnnotation_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/ProcessExecutionDetector.h>
#include <s2e/Plugins/ModuleMap.h>
#include <s2e/Plugins/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

enum S2E_LUA_INS_ANN_COMMANDS {
    REGISTER_ANNOTATION
} __attribute__((aligned(8)));

struct S2E_LUA_INS_ANN_REGISTER {
    uint64_t Pc;
    uint64_t AnnotationNameStr;
} __attribute__((aligned(8)));

struct S2E_LUA_INS_ANN_COMMAND {
    S2E_LUA_INS_ANN_COMMANDS Command;
    union {
        uint64_t Result;
        S2E_LUA_INS_ANN_REGISTER RegisterAnnotation;
    };
} __attribute__((aligned(8)));

class LuaInstructionAnnotation : public Plugin, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN
public:
    LuaInstructionAnnotation(S2E* s2e): Plugin(s2e) {}

    void initialize();


    void handleOpcodeInvocation(S2EExecutionState *state,
                               uint64_t guestDataPtr,
                               uint64_t guestDataSize);
private:

    struct Annotation {
        uint64_t pc;
        std::string annotationName;

        bool operator==(const Annotation &a1) const {
            return pc == a1.pc && annotationName == a1.annotationName;
        }

        bool operator < (const Annotation &a1) const {
            return pc < a1.pc;
        }
    };

    typedef std::set<Annotation> ModuleAnnotations;
    typedef std::map<std::string, ModuleAnnotations *> Annotations;
    Annotations m_annotations;

    ProcessExecutionDetector *m_detector;
    ModuleMap *m_modules;
    sigc::connection m_instructionStart;

    bool registerAnnotation(const std::string &moduleId, const Annotation &annotation);

    void onTranslateBlockStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateInstructionStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc, const ModuleAnnotations *annotations,
            uint64_t addend);

    void onTranslateBlockComplete(
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t ending_pc);

    void onInstruction(S2EExecutionState* state, uint64_t pc,
                       const ModuleAnnotations *annotations, uint64_t modulePc);

    void onMonitorLoad(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaInstructionAnnotation_H
