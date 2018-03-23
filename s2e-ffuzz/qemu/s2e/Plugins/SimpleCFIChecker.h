///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SIMPLECFI_H
#define S2E_PLUGINS_SIMPLECFI_H

#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/ModuleMap.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/Plugins/Vmi.h>
#include <s2e/S2EExecutionState.h>
#include "WindowsMonitor2.h"
#include "MemoryMap.h"

#include "QEMUEvents.h"
#include <s2e/Plugins/ExecutionTracers/UserSpaceTracer.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/IntervalMap.h>

#include <boost/functional/hash.hpp>

namespace s2e {
namespace plugins {

extern "C" {
    void helper_se_call(target_ulong pc);
    void helper_se_ret(target_ulong pc);
}

enum BREAKPOINT_TYPE {
    NT_ALLOCATE_VIRTUAL_MEMORY_EXECUTABLE,
    NT_ALLOCATE_VIRTUAL_MEMORY_NON_EXECUTABLE,
    NT_FREE_VIRTUAL_MEMORY,
    NT_MAP_VIEW_OF_SECTION,
    NT_UNMAP_VIEW_OF_SECTION
};

struct Breakpoint {
    uint64_t brk_addr;
    uint64_t address;
    uint64_t size;
    uint64_t process;
    BREAKPOINT_TYPE type;
};

struct WhitelistedReturn {
    uint32_t src_checksum;
    uint64_t src_addr;
    uint32_t dst_checksum;
    uint64_t dst_addr;

    std::size_t operator()(WhitelistedReturn const &ret) const {
        std::size_t seed = 0;
        boost::hash_combine(seed, ret.src_addr);
        boost::hash_combine(seed, ret.src_checksum);
        boost::hash_combine(seed, ret.dst_addr);
        boost::hash_combine(seed, ret.dst_checksum);
        return seed;
    }

    bool operator==(WhitelistedReturn const& other) const {
        return src_addr == other.src_addr && dst_addr == other.dst_addr &&
               src_checksum == other.src_checksum && dst_checksum == other.dst_checksum;
    }
};



typedef std::pair<uint64_t, uint64_t> SpPc;
typedef std::vector<SpPc> AddressList;

typedef llvm::DenseSet<uint64_t> TrackedPids;

/**
 * Maps a program counter to how many times it appears on the stack.
 */
typedef llvm::DenseMap<uint64_t, unsigned> AddressMap;

//typedef std::tr1::unordered_map<std::pair<uint64_t, uint64_t>, AddressList> StacksMap;

typedef llvm::DenseMap<std::pair<uint64_t,uint64_t>, AddressMap> StacksMap;
typedef llvm::DenseSet<uint64_t> FunctionsSet;

/* Maintains a JIT region map for each process id */
typedef llvm::IntervalMap<uint64_t, bool> JitRegionsMap;

typedef llvm::DenseMap<uint64_t, JitRegionsMap* > JitRegionsMapProcess;

typedef llvm::DenseMap<std::pair<uint64_t,uint64_t>, Breakpoint> BreakpointsMap;
typedef llvm::DenseMap<std::pair<uint64_t,uint64_t>, uint64_t> AllocationsMap;

/* Maps the checksum of the module that generated the code (mso.dll for now) to
 * addresses where it calls FlushInstructionCache. We whitelist the addresses that
 * we find on the stack of these calls.
 */
typedef llvm::DenseMap<uint32_t, std::set<uint64_t>> FlushInstructionCacheMap;

class SimpleCFIChecker : public Plugin, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN
public:
    SimpleCFIChecker(S2E* s2e): Plugin(s2e) {}

    void initialize();

    friend class SimpleCFICheckerState;

    sigc::signal<void,
       S2EExecutionState*,
       bool /* isReturn violation */
    >onCFIViolationDetected;

    //XXX: this event doesn't really belong to CFI
    sigc::signal<void, S2EExecutionState*,
       const S2E_WINMON2_ACCESS_FAULT &
    > onCFIAccessFault;

    //XXX: this event doesn't really belong to CFI either
    sigc::signal<void, S2EExecutionState*,
       std::string
    > onFYISignal;

    //XXX: this event doesn't really belong to CFI either
    sigc::signal<void, S2EExecutionState*,
       std::string
    > onWindowTextSignal;

    //Triggered when there are no more tracked processes
    sigc::signal<void, S2EExecutionState*
    > onAllProcessesTerminated;

    QDict *getStatistics(S2EExecutionState *state) const;
    uint64_t getStatistic(S2EExecutionState *state, const std::string &name) const;

    void stopAnalysis(S2EExecutionState *state);
    TrackedPids getTrackedPids(S2EExecutionState *state) const;

    const AddressMap &getAddressMap(S2EExecutionState *state) const;
private:
    JitRegionsMap::Allocator alloc;

    typedef std::tr1::unordered_set<std::string> StringSet;
    WindowsMonitor2 * m_monitor;
    ModuleMap *m_map;
    MemoryMap *m_memory;
    Vmi *m_vmi;
    UserSpaceTracer *m_tracer;

    bool m_verbose;
    bool m_dumpRegions;
    bool m_terminateOnJITIdle;

    bool m_ignoreViolationOnCrash;
    bool m_reportAccessFaults;
    uint64_t m_clockSlowDownFactor;

    uint64_t m_firstTrackedModuleTime;

    sigc::connection m_onTbEnd;
    sigc::connection m_onTbComplete;

    //List of modules whose calls we want to track.
    //Empty to track all modules in the system.
    StringSet m_trackedModules;

    //Ignore violations in these modules
    StringSet m_whiteListedModulePaths;

    //Ignore specific return violations
    std::tr1::unordered_set<WhitelistedReturn, WhitelistedReturn> m_whitelistedReturns;

    FlushInstructionCacheMap m_flushInstructionCacheCalls;

    llvm::raw_ostream &getWarningsStream(uint64_t pid = 0, uint64_t tid = 0) const {
        return Plugin::getWarningsStream() << "(" << hexval(pid) << ":" << hexval(tid) << "): ";
    }

    llvm::raw_ostream &getDebugStream(uint64_t pid = 0, uint64_t tid = 0) const {
        return Plugin::getDebugStream() << "(" << hexval(pid) << ":" << hexval(tid) << "): ";
    }

    bool isWhitelistedReturn(const ModuleDescriptor *src, uint64_t srcAddr, const ModuleDescriptor *dst, uint64_t dstAddr);
    bool isGeneratedTrampoline(S2EExecutionState *state, uint64_t caller);

    bool setupViolationConfirmation(S2EExecutionState *state, uint64_t monitorPc, bool isCall);

    void getPeFromDisk(const ModuleDescriptor &module);
    void readModInfo(const ModuleDescriptor &, S2EExecutionState *state, vmi::PEFile *file, uint64_t diff, uint64_t exportsDiff, FunctionsSet &functions);
    bool readModInfoFromFile(const ModuleDescriptor &, S2EExecutionState *state, std::string path, uint64_t loadBase, FunctionsSet &functions);

    void scanModule(S2EExecutionState *state, const ModuleDescriptor &module);

    void onMonitorLoad(S2EExecutionState *state);

    void onModuleLoad(
            S2EExecutionState* state,
            const ModuleDescriptor &module
            );

    void onModuleUnload(
            S2EExecutionState* state,
            const ModuleDescriptor &module
            );

    void addFunctionFromInstruction(S2EExecutionState *state, uint64_t pc, uint64_t addr, bool checkRange);

    void onTranslateSpecialInstructionEnd(ExecutionSignal *signal,
                                           S2EExecutionState *state,
                                           TranslationBlock *tb,
                                           uint64_t pc,
                                           enum special_instruction_t  type);

    void onTranslateLeaRipRelative(ExecutionSignal *signal,
                                   S2EExecutionState *state,
                                   TranslationBlock*,
                                   uint64_t, uint64_t addr);

    void onTranslateBlockStart(ExecutionSignal *signal,
                               S2EExecutionState *state,
                               TranslationBlock *tb,
                               uint64_t pc);

    void onTranslateInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                   TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onCfiCallReturnTranslate(S2EExecutionState *state,
                                  uint64_t pc, bool isCall, bool *instrument);

    void onTranslateBlockEnd(ExecutionSignal*, S2EExecutionState *state,
                             TranslationBlock *tb, uint64_t pc,
                             bool, uint64_t);

    void onTbEndInstrument(ExecutionSignal*, S2EExecutionState *state,
                           TranslationBlock *tb, uint64_t pc,
                           bool, uint64_t);

    void onTbComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endpc);
    void onTranslateJumpStart(ExecutionSignal *signal,
                                S2EExecutionState *state,
                                TranslationBlock*,
                                uint64_t, int jump_type);

    void onFunctionExec(S2EExecutionState* state, uint64_t pc);
    void onGenerateTrampoline(S2EExecutionState *state, uint64_t pc);

    void onCFIViolationConfirm(S2EExecutionState *state, uint64_t pc);
    void onCall(S2EExecutionState* state, uint64_t pc);
    void onRet(S2EExecutionState* state, uint64_t pc);

    void handleOnCallBreakpoints(S2EExecutionState *state, uint64_t pid, uint64_t tid,
                                uint64_t caller, uint64_t callee, uint64_t returnAddress);

    void handleOnRetBreakpoints(S2EExecutionState *state,
                                 uint64_t pid,
                                 uint64_t tid,
                                 uint64_t addr);

    void onProcessOrThreadSwitch(S2EExecutionState *state);

    void onAccessFault(S2EExecutionState *state, const S2E_WINMON2_ACCESS_FAULT &AccessFault);

    void onFYINotification(S2EExecutionState *state, std::string info);
    void onWindowInfo(S2EExecutionState *state, std::string info);
    void takeScreenShot(S2EExecutionState *state);

    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &ImageFileName);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid);

    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &desc);

    void onTimer(void);

    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);

    //analysis termination helpers
    uint64_t m_timerCount;
    unsigned m_timerTicks;
    bool m_stopRequested;
    void stopIfJITCodeNotRunning(S2EExecutionState *state);
    bool isJitTarget(S2EExecutionState *state, uint64_t pid, uint64_t callee);
    bool isDataSectionJit(S2EExecutionState *state, uint64_t pid,
                          const ModuleDescriptor *mod, uint64_t pc);

    /************************************************/
    void onNtAllocateVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_ALLOCATE_VM &d);
    void onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &d);
    void onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &d);
    void onNtMapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_MAP_SECTION &d);
    void onNtUnmapViewOfSection(S2EExecutionState *state, const S2E_WINMON2_UNMAP_SECTION &d);

    friend void helper_se_call(target_ulong pc);
    friend void helper_se_ret(target_ulong pc);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SIMPLECFI_H
