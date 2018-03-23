/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Written by Bin Zhang <bin.zhang@epfl.ch>
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef FUZZYS2E_H_

#define FUZZYS2E_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/FunctionMonitor.h>
#include <s2e/Plugins/BaseInstructions.h>
#include <s2e/Plugins/HostFiles.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/Plugins/Linux/LinuxMonitor2.h>

#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <klee/Searcher.h>
#include <vector>
#include <set>
#include "klee/util/ExprEvaluator.h"
#include <llvm/Support/TimeValue.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>


#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/TreeStream.h"
#include "klee/AddressSpace.h"
#include "klee/Internal/Module/KInstIterator.h"
#include "klee/Internal/Support/Timer.h"
#include "klee/util/Assignment.h"
#include "klee/Memory.h"

#include <s2e/Plugins/X86ExceptionInterceptor.h>

#include "TestcaseFilter.h"

using namespace llvm::sys;
namespace s2e {
namespace plugins {

struct S2E_FUZZYS2EMONITOR_MODULE_LOAD {
    uint64_t path;
    uint64_t name;
    uint64_t nativeBase;
    uint64_t loadBase;
    uint64_t entryPoint;
    uint64_t size;
    uint64_t pid;
    uint64_t kernelMode;
} __attribute__((aligned(8)));


enum S2E_FUZZYS2EMONITOR_COMMANDS {
    ONMODULE_LOAD
}__attribute__((aligned(8)));

struct S2E_FUZZYS2EMONITOR_COMMAND {
    S2E_FUZZYS2EMONITOR_COMMANDS Command;
    union {
        S2E_FUZZYS2EMONITOR_MODULE_LOAD ModuleLoad;
    };
};


class FuzzyS2E;

class FuzzyS2EState: public PluginState
{
public:
    FuzzyS2E* m_plugin;
    S2EExecutionState *m_state;
public:
    std::map<uint64_t, uint64_t> pc_hits;
    //in order to improve efficiency, we write the branches of S2E to AFL's bitmap
    uint32_t m_prev_loc; //previous location when executing
    klee::WallTimer *m_ExecTime;
    uint8_t m_fault;
    FuzzyS2EState();
    virtual ~FuzzyS2EState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    inline bool updateAFLBitmapSHM(unsigned char* bitmap, uint32_t pc);


    friend class FuzzyS2E;
};

/*
 * Duplicated code from AFL.
 */

#define AFL_BITMAP_SIZE (1 << 16)

// QEMU instances queue (as a file)
#define QEMUQUEUE "/tmp/afl_qemu_queue"
#define FIFOBUFFERSIZE 512
// Test cases directory
#define TESTCASEDIR "/tmp/afltracebits/"
// Every control pipe
#define CTRLPIPE(_x) (_x + 226)
// Share memory ID
#define READYSHMID 1234

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_HANG,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,  // Unable to execute target application.
  /* 04 */ FAULT_NOINST, // impossible
  /* 05 */ FAULT_NOBITS,  // impossible
  /* 06 */ FAULT_REDUNDANT // Marked as a redundant testcase
};

#define SMKEY 0x200 // MUST BE EQUAL to what in afl
class FuzzyS2E: public Plugin, public klee::Searcher, public BaseInstructionsPluginInvokerInterface
{
S2E_PLUGIN

private:
    void onCustomInstruction(
            S2EExecutionState *state,
            uint64_t operand
            );
    bool getAFLBitmapSHM();
    bool initQemuQueue();
    bool initReadySHM();

    void wait_afl_testcase(S2EExecutionState *state);
    void tell_afl(S2EExecutionState *state, bool ReserveState = true);
    void fork_work_state(S2EExecutionState *state);
    void wait_work_state(S2EExecutionState *state);
    void report_redundant(void);
    void RemoveUnscheduleState(S2EExecutionState *state);
    bool generateCaseFile(S2EExecutionState *state, std::string destfilename);
    void handleModuleLoad(S2EExecutionState *state, const S2E_FUZZYS2EMONITOR_MODULE_LOAD &m);
    void handleOpcodeInvocation(S2EExecutionState *state,
                                uint64_t guestDataPtr,
                                uint64_t guestDataSize);

    uint64_t m_current_conditon = 0;

public:
    struct SortById
    {
        bool operator ()(const klee::ExecutionState *_s1,
                const klee::ExecutionState *_s2) const
        {
            const S2EExecutionState *s1 =
                    static_cast<const S2EExecutionState*>(_s1);
            const S2EExecutionState *s2 =
                    static_cast<const S2EExecutionState*>(_s2);

            return s1->getID() < s2->getID();
        }
    };
    typedef std::set<klee::ExecutionState*, SortById> States;

    typedef std::set<std::string> StringSet;
    typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;


    std::vector<klee::ExecutionState*> m_schedule_states;

    klee::ExecutionState& selectState();
    void update(klee::ExecutionState *current,
    		const klee::StateSet &addedStates,
    		const klee::StateSet &removedStates);

    bool empty() { return m_schedule_states.empty(); }

private:
    /*
     * If cannot cover new path after m_drillFreq testcases, then use symbex to
     * generate a new one.
     * This function only be switched on when using testcase filter.
     */
    bool                m_useDrill;
    uint32_t            m_drillFreq;
    uint32_t            m_DrillFreqCounter;
    bool                m_has_dummy_symb;
    klee::ref<klee::Expr> m_dummy_symb;
    uint64_t            m_exeTimeout;
    bool                m_parsedModInfo;
    ModuleDescriptor    m_mainModuleDes;

public:
    /**
     * schdualer
     */
    unsigned char* m_aflBitmapSHM; //AFL's trace bits bitmap
    bool m_findBitMapSHM; //whether we have find trace bits bitmap

    std::string m_genTestcaseDir;   //Drill initial directory
    std::string m_testcaseDir;
    std::string m_filename;
    // AFL end
    std::string m_mainModule;	//main module name (i.e. target binary)
    uint64_t m_mainPid;         //main process PID
    unsigned char m_caseGenetated[AFL_BITMAP_SIZE]; // branches we have generated case

    int m_shmID;
    uint32_t m_QEMUPid;
    uint32_t m_PPid;
    int m_queueFd;
    uint8_t* m_ReadyArray;
    uint64_t m_lastID;

    bool m_verbose; //verbose debug output
    bool m_needFilter; // set to true if want testcase filter
    /* Kill states that cannot cover new path to avoid memory overhead. */
    bool m_killRState; // set to true if want to kill redundant states

    HostFiles* m_HostFiles;
    LinuxMonitor2* m_LinuxMonitor2;
    TestcaseFilter* m_TestcaseFilter;

public:
    FuzzyS2E(S2E* s2e) :
            Plugin(s2e)
    {
        m_shmID = 0;
        m_mainPid = 0;
        m_QEMUPid = 0;
        m_queueFd = -1;
        m_aflBitmapSHM = 0;
        m_findBitMapSHM = false;
        m_verbose = false;
        m_has_dummy_symb = false;
        m_parsedModInfo = false;
    }
    virtual ~FuzzyS2E();
    virtual void initialize();

    void onTranslateBlockStart(ExecutionSignal*, S2EExecutionState*, TranslationBlock*, uint64_t);
    void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

    void onSegmentFault(S2EExecutionState*, uint64_t, uint64_t);
    void onDividebyZero(S2EExecutionState*, uint64_t, uint64_t, bool);

    void onProcessUnload(S2EExecutionState*, uint64_t, uint64_t);

    void onWorkStateTimeout(S2EExecutionState*);

    void onStateFork(S2EExecutionState* /* originalState */,
                     const std::vector<S2EExecutionState*>& /* newStates */,
                     const std::vector<klee::ref<klee::Expr> >& /* newConditions */);
    inline void onStateForkDecide(S2EExecutionState * state, bool* forkOK) {
        *forkOK = !state->getID() || isMainImage(state->getPc());
    }
    inline bool isMainImage(uint64_t pc) {
        return pc >= m_mainModuleDes.LoadBase && pc <= (m_mainModuleDes.LoadBase+m_mainModuleDes.Size);
    }

};
}
} /* namespace s2e */

#endif /* !FUZZYS2E_H_ */

