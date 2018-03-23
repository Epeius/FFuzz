///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_StaticLibraryFunctionModels_H
#define S2E_PLUGINS_StaticLibraryFunctionModels_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/Vmi.h>

#include <llvm/ADT/StringMap.h>

namespace s2e {
namespace plugins {

class StaticLibraryFunctionModels : public Plugin
{
    S2E_PLUGIN
public:
    StaticLibraryFunctionModels(S2E* s2e): Plugin(s2e) {}
    ~StaticLibraryFunctionModels();

    void initialize();

    unsigned getFunctionModelCount() const;

private:
    typedef bool (StaticLibraryFunctionModels::*OpHandler)(S2EExecutionState *state, uint64_t pc);
    typedef llvm::StringMap<OpHandler> HandlerMap;

    ModuleExecutionDetector *m_detector;
    Vmi *m_vmi;
    HandlerMap m_handlers;

    std::map<std::string /* moduleName */, Vmi::BinData> m_binaries;

    void onModuleTranslateBlockEnd(
            ExecutionSignal *signal,
            S2EExecutionState  *state,
            const ModuleDescriptor &module,
            TranslationBlock *tb,
            uint64_t endPc,
            bool staticTarget,
            uint64_t targetPc);

    bool getBool(S2EExecutionState *state, const std::string &property);

    void readSymbolicString(S2EExecutionState *state, uint64_t concretePtr,
                            std::vector<klee::ref<klee::Expr> > &ret);

    void printString(S2EExecutionState *state,
                     std::vector<klee::ref<klee::Expr> > &str,
                     llvm::raw_ostream &ofs);

    klee::ref<klee::Expr> readMemory8(S2EExecutionState *state, uint64_t addr);
    bool readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg);
    bool findNullChar(S2EExecutionState *state, uint64_t stringAddr, size_t &len);
    bool stringCompareExplicit(S2EExecutionState *state, bool hasMaxSize);
    bool handleStrlenExplicit(S2EExecutionState *state, uint64_t pc);
    bool handleStrcmpExplicit(S2EExecutionState *state, uint64_t pc);
    bool handleStrncmpExplicit(S2EExecutionState *state, uint64_t pc);
    bool handleMemcmpExplicit(S2EExecutionState *state, uint64_t pc);
    bool handleNop(S2EExecutionState *state, uint64_t pc);
    bool handleStrtolExplicit(S2EExecutionState *state, uint64_t pc);

    bool handleStrncmp(S2EExecutionState *state, uint64_t pc);
    bool handleStrsep(S2EExecutionState *state, uint64_t pc);
    bool handleStrcpy(S2EExecutionState *state, uint64_t pc);
    bool handleStrtok(S2EExecutionState *state, uint64_t pc);
    bool handleStrchr(S2EExecutionState *state, uint64_t pc);
    bool handleStrstr(S2EExecutionState *state, uint64_t pc);
    bool handleMemcmp(S2EExecutionState *state, uint64_t pc);


    void checkFormatString(S2EExecutionState *state, uint64_t ptr);
    bool handlePrintf(S2EExecutionState *state, uint64_t pc);
    bool handleFdprintf(S2EExecutionState *state, uint64_t pc);
    bool handleVprintf(S2EExecutionState *state, uint64_t pc);
    bool handleFprintf(S2EExecutionState *state, uint64_t pc);
    bool handleVsnprintf(S2EExecutionState *state, uint64_t pc);

    void onCall(S2EExecutionState *state, uint64_t pc, OpHandler handler);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_StaticLibraryFunctionModels_H
