///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_ControlFlowGraph_H
#define S2E_PLUGINS_ControlFlowGraph_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/BaseInstructions.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>

namespace s2e {
namespace plugins {

typedef enum _S2E_CFG_COMMANDS {
    CFG_REGISTER_FUNCTION
} S2E_CFG_COMMANDS __attribute__((aligned(8)));

typedef struct _S2E_CFG_FUNCTION {
    uint64_t RunTimeFunctionAddress;
    uint64_t FunctionName;
} S2E_CFG_FUNCTION __attribute__((aligned(8)));

typedef struct _S2E_CFG_COMMAND {
    S2E_CFG_COMMANDS Command;
    union {
        S2E_CFG_FUNCTION Function;
    };
} S2E_CFG_COMMAND  __attribute__((aligned(8)));

///
/// \brief The ControlFlowGraph class represents a CFG
///
class ControlFlowGraph : public Plugin, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN
public:
    ControlFlowGraph(S2E* s2e): Plugin(s2e) {}

    void initialize();

    typedef llvm::SmallVector<uint64_t, 2> ProgramCounters;

    //Maps a function entry block to a function name
    typedef llvm::DenseMap<uint64_t, std::string> FunctionEntryPoints;

    struct BasicBlock {
        uint64_t start_pc;
        uint64_t end_pc;
        unsigned size;
        uint64_t call_target;
        ProgramCounters successors;
        ProgramCounters predecessors;

        BasicBlock() {
            start_pc = end_pc = 0;
            size = 0;
        }

        //TODO: take into account the size
        bool operator < (const BasicBlock &bb) const {
            return start_pc + size <= bb.start_pc;
        }
    };

    typedef std::set<BasicBlock> BasicBlocks;
    typedef std::map<std::string, BasicBlocks> ModuleBasicBlocks;

    typedef std::map<std::string, FunctionEntryPoints> ModuleFunctions;

    sigc::signal<void> onReload;

    const BasicBlock* findBasicBlock(const std::string &module, uint64_t pc) const;

    bool getBasicBlockRange(const std::string &module, uint64_t start, uint64_t end,
                            std::vector<const BasicBlock*> &blocks);

    uint64_t getBasicBlockCount(const std::string &module) const;
    uint64_t getBasicBlockCount() const {
        return m_basicBlockCount;
    }

    /**
     * Follows a chain of basic blocks linked together by direct jumps.
     * Return the pc of the first basic block that has multiple targets.
     */
    bool getFinalSuccessor(const std::string &module, uint64_t start, uint64_t *end) const;

    bool getFunctionName(const std::string &module, uint64_t entry_point, std::string &name) const;

    bool isReachable(const std::string &module, uint64_t source, uint64_t dest, bool &result) const;
    bool isReachable(const BasicBlocks &bbs, uint64_t source, uint64_t dest, bool &result) const;

private:
    ModuleExecutionDetector *m_detector;
    ModuleFunctions m_entryPoints;
    ModuleBasicBlocks m_basicBlocks;

    uint64_t m_basicBlockCount;

    void loadConfiguration();
    const BasicBlock* findBasicBlock(const BasicBlocks &bbs, uint64_t pc) const;

    void onTimer();

    /* Guest config interface */
    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ControlFlowGraph_H
