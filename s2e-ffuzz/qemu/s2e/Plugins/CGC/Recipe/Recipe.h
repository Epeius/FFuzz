///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_Recipe_H_
#define S2E_PLUGINS_Recipe_H_

#include <s2e/cpu.h>

#include <s2e/Plugin.h>
#include <s2e/Plugins/ProcessExecutionDetector.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/CGC/POVGenerator.h>
#include <s2e/Plugins/StackMonitor.h>
#include <s2e/Plugins/Searchers/SeedSearcher.h>
#include <s2e/Plugins/KeyValueStore.h>
#include <klee/Expr.h>

#include "RecipeDescriptor.h"

namespace s2e {
namespace plugins {
namespace recipe {

struct MemPrecondition
{
    Preconditions preconditions;
    klee::ref<klee::Expr> ptrExpr;
    unsigned requiredMemSize;
    bool exec; // must be executable
    MemPrecondition(): requiredMemSize(0), exec(false) {}
};

struct AddrSize
{
    uint64_t addr;
    size_t size;

    AddrSize(uint64_t addr, size_t size): addr(addr), size(size) {}

    bool operator <(const AddrSize& x) const {
        return (size < x.size);
    }
};

typedef std::map<std::string, RecipeDescriptor *> RecipeMap;
typedef CGCMonitor::SymbolicBufferType SymbolicBufferType;

struct RecipeStats {
    /// Number of recipes that couldn't be parsed
    unsigned invalidRecipeCount;

    /// Number of times all recipes failed
    /// to apply to an execution state
    unsigned failedRecipeTries;

    /// Number of times at least one recipe
    /// could be applied to an execution state
    unsigned successfulRecipeTries;

    RecipeStats() {
        invalidRecipeCount = 0;
        failedRecipeTries = 0;
        successfulRecipeTries = 0;
    }
};

inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const RecipeStats& s)
{
    out << "RecipeStats invalidCount: " << s.invalidRecipeCount
        << " failedTries: " << s.failedRecipeTries
        << " successTries: " << s.successfulRecipeTries;

    return out;
}

class Recipe : public Plugin
{
    S2E_PLUGIN
public:
    Recipe(S2E* s2e): Plugin(s2e) {}

    void initialize();

    sigc::signal<void, S2EExecutionState*, const PovOptions &, const std::string & /* recipeName */> onPovReady;

private:
    CGCMonitor *m_monitor;
    ProcessExecutionDetector *m_process;
    ModuleExecutionDetector *m_detector; // TODO: this is a deprecated plugin
    StackMonitor *m_stackMonitor;
    seeds::SeedSearcher *m_seedSearcher;
    KeyValueStore *m_keyValueStore;

    RecipeMap m_recipes;
    uint64_t m_lastRecipeLoadTime;
    std::string m_recipesDir;

    RecipeStats m_stats;

    uint32_t m_flagPage;

    void onTimer();

    void loadRecipesFromDirectory(const std::string &directory);

    void instrumentCTI(ExecutionSignal *signal, S2EExecutionState *state,
                       TranslationBlock *tb, uint64_t pc, bool isStatic,
                       uint64_t staticTarget);
    void onTranslateJumpStart(ExecutionSignal *signal,
                              S2EExecutionState *state, TranslationBlock *tb,
                              uint64_t pc, int jump_type);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool isStatic, uint64_t staticTarget);

    void onAfterCall(S2EExecutionState *state, uint64_t callInstructionPc);

    void handleICTI(S2EExecutionState *state, uint64_t pc, unsigned rm, int op, int offset);
    void onTranslateICTIStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                              uint64_t pc, int rm, int op, int offset);

    void onSymbolicAddress(S2EExecutionState *state,
                           klee::ref<klee::Expr> virtualAddress,
                           uint64_t concreteAddress,
                           bool &concretize,
                           CorePlugin::symbolicAddressReason reason);

    void onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state,
                                          klee::ref<klee::Expr> addr,
                                          klee::ref<klee::Expr> value,
                                          bool isWrite);

    void onBeforeRet(S2EExecutionState *state, uint64_t pc);

    bool exprIn(klee::ref<klee::Expr> expr, const ExprList &a);
    void extractSymbolicBytes(const klee::ref<klee::Expr> &e, ExprList &bytes);

    klee::ref<klee::Expr> getRegbyteExpr(S2EExecutionState *state, const StateConditions& sc, Register r);
    klee::ref<klee::Expr> getRegExpr(S2EExecutionState *state, const StateConditions& sc, Register r);
    bool getLeftExpr(S2EExecutionState *state, const StateConditions& sc, const Precondition &p,
                     klee::ref<klee::Expr>& left);
    bool isSymbolicRegPtr(S2EExecutionState *state, const StateConditions& sc, const Left &l,
                          klee::ref<klee::Expr> &ptrExpr);

    void pruneSymbolicSequences(S2EExecutionState *state, const ExprList &usedExprs, std::vector<AddrSize> &list);

    bool applySimplePrecondition(S2EExecutionState *state, const StateConditions& sc,
                                 const klee::ref<klee::Expr> &left, const Right &right,
                                 RecipeConditions &recipeConditions);
    bool testMemPrecondition(S2EExecutionState *state, const StateConditions& sc, const MemPrecondition &p,
                             AddrSize sequence, const RecipeConditions &recipeConditions, uint32_t &offset);
    bool applyMemPrecondition(S2EExecutionState *state, const StateConditions& sc, const MemPrecondition &p,
                              RecipeConditions &recipeConditions);

    void classifyPreconditions(S2EExecutionState *state, const StateConditions& sc, const Preconditions &p,
            Preconditions &simple, std::map<Register::Reg, MemPrecondition> &memory);
    bool applyPreconditions(S2EExecutionState *state, PovType type, const StateConditions& sc, const Preconditions &p,
                            RecipeConditions &recipeConditions);
    bool tryRecipes(S2EExecutionState *state, const StateConditions &sc, RecipeConditions &recipeConditions);

    void tryRecipesOnICTI(S2EExecutionState *state, klee::ref<klee::Expr> regExpr, Register reg, int ictiOffset);

    bool checkUsedRegs(S2EExecutionState *state, const Left &left, const RegList &usedRegs);

    bool getCurrentModule(S2EExecutionState *state, uint64_t eip, ModuleDescriptor& module);

    void suppressExecutionWithInvalidAddress(S2EExecutionState *state, klee::ref<klee::Expr> addr, bool isWrite, int accessSize);
    void handleSymbolicWrite(S2EExecutionState *state, klee::ref<klee::Expr> addr);

    void handleSymbolicRead(S2EExecutionState *state, klee::ref<klee::Expr> addr);

    void onSymbolicBuffer(S2EExecutionState *state, uint64_t pid, SymbolicBufferType type, klee::ref<klee::Expr> ptr, klee::ref<klee::Expr> size);

public:

    const RecipeStats &getStats() const {
        return m_stats;
    }

    void resetStats() {
        m_stats = RecipeStats();
    }

    unsigned getRecipeCount() const {
        return m_recipes.size();
    }
};

} // namespace recipe
} // namespace plugins
} // namespace s2e

#endif /* S2E_PLUGINS_Recipe_H_ */
