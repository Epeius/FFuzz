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

extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include <sysemu.h>
#include <sys/shm.h>
}
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Opcodes.h>
#include <s2e/Utils.h>

#include <iomanip>
#include <cctype>

#include <algorithm>
#include <fstream>
#include <vector>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>    /**/
#include <errno.h>     /*errno*/
#include <unistd.h>    /*ssize_t*/
#include <sys/types.h>
#include <sys/stat.h>  /*mode_t*/
#include <stdlib.h>

#include "FuzzyS2E.h"
extern int errno;
extern unsigned const_arr_id;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FuzzyS2E, "FuzzyS2E plugin", "FuzzyS2E enables to play with fuzzing test.",
        "LinuxMonitor2", "HostFiles");


FuzzyS2E::~FuzzyS2E()
{
}
void FuzzyS2E::initialize()
{
    bool ok = false;
    std::string cfgkey = getConfigKey();
    m_HostFiles = (HostFiles*)s2e()->getPlugin("HostFiles");
    m_verbose = s2e()->getConfig()->getBool(getConfigKey() + ".debugVerbose",
            false, &ok);

    m_needFilter = s2e()->getConfig()->getBool(getConfigKey() + ".needFilter", false, &ok);
    m_killRState = s2e()->getConfig()->getBool(getConfigKey() + ".killRedundantState", false, &ok);
    m_useDrill   = s2e()->getConfig()->getBool(getConfigKey() + ".useDrill", false, &ok);
    m_drillFreq  = s2e()->getConfig()->getInt(getConfigKey() + ".drillFreq", 100);
    m_exeTimeout  = s2e()->getConfig()->getInt(getConfigKey() + ".exeTimeout", 1000000);
    if (m_killRState || m_useDrill)
        assert(m_needFilter && "Only work under testcase filter mode!");
    if (m_useDrill)
        m_DrillFreqCounter = m_drillFreq;
    
    m_mainModule = s2e()->getConfig()->getString(cfgkey + ".mainModule", "MainModule", &ok);
    m_genTestcaseDir = s2e()->getConfig()->getString(cfgkey + ".genTestcaseDir", "SYMBEX", &ok);
    m_filename = s2e()->getConfig()->getString(cfgkey + ".filename", "test.case", &ok);
    
    if (m_needFilter) {
        m_TestcaseFilter = static_cast<TestcaseFilter*>(s2e()->getPlugin("TestcaseFilter"));
        if (!m_TestcaseFilter) {
            std::cerr << "Could not find TestcaseFilter plug-in. " << '\n';
            exit(0);
        }
    }
    
    m_LinuxMonitor2 = static_cast<LinuxMonitor2*>(s2e()->getPlugin("LinuxMonitor2"));
    if (!m_LinuxMonitor2) {
        std::cerr << "Could not find LinuxMonitor2 plug-in. " << '\n';
        exit(0);
    }
    m_LinuxMonitor2->onDividebyZero.connect(sigc::mem_fun(*this, &FuzzyS2E::onDividebyZero));
    m_LinuxMonitor2->onSegmentFault.connect(sigc::mem_fun(*this, &FuzzyS2E::onSegmentFault));
    m_LinuxMonitor2->onProcessUnload.connect(sigc::mem_fun(*this, &FuzzyS2E::onProcessUnload));

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onTranslateBlockStart));
    s2e()->getCorePlugin()->onCustomInstruction.connect(
                                        sigc::mem_fun(*this, &FuzzyS2E::onCustomInstruction));
    if (m_useDrill) {
        s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &FuzzyS2E::onStateForkDecide));
        s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &FuzzyS2E::onStateFork));
    }
    
    m_QEMUPid = getpid();
    m_PPid = getppid();
    
    if (!m_findBitMapSHM)
        m_findBitMapSHM = getAFLBitmapSHM();
    assert(m_aflBitmapSHM && "AFL's trace bits bitmap is NULL, why??");
    if(!initReadySHM())
        exit(EXIT_FAILURE);
    if(!initQemuQueue())
        exit(EXIT_FAILURE);

    std::stringstream testcase_strstream;
    testcase_strstream << "/tmp/afltestcase/" << m_QEMUPid;
    if (::access(testcase_strstream.str().c_str(), F_OK)) // for all testcases
        mkdir(testcase_strstream.str().c_str(), 0777);
    m_testcaseDir = testcase_strstream.str();
    if(!m_HostFiles->addDirectories(m_testcaseDir))
        exit(EXIT_FAILURE);
    testcase_strstream << "/" << m_filename;
    m_filename = testcase_strstream.str(); // construct full path name

    s2e()->getExecutor()->setSearcher(this);
}

klee::ExecutionState& FuzzyS2E::selectState()
{
	// The size of states can reach to 3 when using symbex to assist fuzzing.
    assert((m_schedule_states.size() < 3) && "States number is weird!" );
    return *(m_schedule_states.size() == 1 ? m_schedule_states[0] : m_schedule_states[1]);
}

// Code from RandomSearcher
void FuzzyS2E::update(klee::ExecutionState *current,
		const klee::StateSet &addedStates,
		const klee::StateSet &removedStates)
{
    m_schedule_states.insert(m_schedule_states.end(),
				  addedStates.begin(),
				  addedStates.end());
	for (klee::StateSet::const_iterator it = removedStates.begin(),
		 ie = removedStates.end(); it != ie; ++it) {
		klee::ExecutionState *es = *it;
		bool ok = false;

		for (std::vector<klee::ExecutionState*>::iterator it = m_schedule_states.begin(),
			 ie = m_schedule_states.end(); it != ie; ++it) {
			if (es==*it) {
			    m_schedule_states.erase(it);
				ok = true;
				break;
			}
		}
	}
}

void FuzzyS2E::onTranslateBlockStart(ExecutionSignal* es,
        S2EExecutionState* state, TranslationBlock* tb, uint64_t pc)
{
    if (!tb || !m_mainPid) {
        return;
    }
    if (m_LinuxMonitor2->getPid(state, pc) == m_mainPid)
        es->connect(sigc::mem_fun(*this, &FuzzyS2E::slotExecuteBlockStart));
}

void FuzzyS2E::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    if (!state->getID())
        return;
    if (m_LinuxMonitor2->isKernelAddress(pc))
        return;
    if (m_verbose){
        s2e()->getDebugStream(state) << "Executing BB at " << hexval(pc) << "\n";
        s2e()->getDebugStream(state).flush();
    }

    if (!isMainImage(pc))
        return;
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    plgState->updateAFLBitmapSHM(m_aflBitmapSHM, pc);
    if (plgState->m_ExecTime->check() > m_exeTimeout)
        onWorkStateTimeout(state);
}

void FuzzyS2E::onWorkStateTimeout(S2EExecutionState *state)
{
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    plgState->m_fault = FAULT_NONE;
    tell_afl(state, false);
    if (m_needFilter)
        m_TestcaseFilter->cleanup(state->getID());
    s2e()->getExecutor()->terminateStateEarly(*state, "Execution timeout!");
}

#define CHKPID(_x)    \
    do {                    \
    if (_x != m_mainPid)  \
        return;           \
    } while (0)

void FuzzyS2E::onSegmentFault(S2EExecutionState* state, uint64_t pid, uint64_t pc)
{
    CHKPID(pid);
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    plgState->m_fault = FAULT_CRASH;
    tell_afl(state);
    if (!m_needFilter) // if not use filter, kill this state
        s2e()->getExecutor()->terminateStateEarly(*state, "Segment fault bug!");
}

void FuzzyS2E::onDividebyZero(S2EExecutionState* state, uint64_t pid, uint64_t pc, bool isFloat)
{
    CHKPID(pid);
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    plgState->m_fault = FAULT_CRASH;
    tell_afl(state);
    if (!m_needFilter) // if not use filter, kill this state
        s2e()->getExecutor()->terminateStateEarly(*state, "Divided by Zero bug!");
}

/*
 * After detect process unload, guest needs to do extra work to cleanup the execution. So once
 * detected process unload, we kill current state and notify AFL.
 */
void FuzzyS2E::onProcessUnload(S2EExecutionState* state, uint64_t cr3, uint64_t pid)
{
    CHKPID(pid);
    tell_afl(state); // Assume all the exceptions will be captured before unloading, so keep default.
    if (!m_needFilter) // if not use filter, kill this state
        s2e()->getExecutor()->terminateStateEarly(*state, "target process unloaded!");
    else{
        if (m_TestcaseFilter->getSigStates().size() >= m_TestcaseFilter->getMAXstates())
            s2e()->getExecutor()->terminateStateEarly(*state, "extra state killed!");
    }
}

// When state forking, kill states for testcase generation
void FuzzyS2E::onStateFork(S2EExecutionState*  originalState,
        const std::vector<S2EExecutionState*>& newStates,
        const std::vector<klee::ref<klee::Expr> >& newConditions)
{
    int oriID = originalState->getID();
    if (!oriID)
        return;

    DECLARE_PLUGINSTATE(FuzzyS2EState, originalState);

    auto pc_hits_it = plgState->pc_hits.find(originalState->getPc());
    if (pc_hits_it == plgState->pc_hits.end()) {
        plgState->pc_hits.insert(std::make_pair(originalState->getPc(), 1));
    } else {
        plgState->pc_hits[originalState->getPc()] += 1;
    }

    auto newit = newStates.begin();
    for (; newit != newStates.end(); newit++) {
        S2EExecutionState* _state = *newit;
        if (_state->getID() == oriID)
            continue;
        if (m_TestcaseFilter->checkRedundantFast(_state, plgState->pc_hits[originalState->getPc()])) {
            s2e()->getDebugStream() << "FuzzyS2E: This state will not generate an interesting testcase!\n";
            s2e()->getExecutor()->terminateStateEarly(*_state, "Terminate for testcase generation!");
            continue;
        }

        std::stringstream gen_testcase_strstream;
        gen_testcase_strstream << m_genTestcaseDir << "/" << m_QEMUPid << "-" << _state->getID();
        std::string gen_testcase = gen_testcase_strstream.str();
        if (generateCaseFile(_state, gen_testcase))
            s2e()->getDebugStream() << "FuzzyS2E: Successfully generate testcase for state-" << _state->getID() << ".\n";
        s2e()->getExecutor()->terminateStateEarly(*_state, "Terminate for testcase generation!");
    }
}

bool FuzzyS2E::generateCaseFile(S2EExecutionState *state,
        std::string destfilename)
{
    //try to solve the constraint and write the result to destination file
    ConcreteInputs out;
    //XXX: we have to create a new temple state, otherwise getting solution in half of a state may drive to crash
    klee::ExecutionState* exploitState = new klee::ExecutionState(*state);
    bool success = s2e()->getExecutor()->getSymbolicSolution(*exploitState, out);

    if (!success) {
        s2e()->getWarningsStream() << "Could not get symbolic solutions"
                << '\n';
        delete(exploitState);
        return false;
    }

    std::ofstream destfile;
    destfile.open (destfilename.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);

    ConcreteInputs::iterator it;
    for (it = out.begin(); it != out.end(); ++it) {
        const VarValuePair &vp = *it;
        std::string varname = vp.first;
        std::size_t found = varname.find("dummy");
        if (found != std::string::npos)
            continue;

        unsigned wbuffer[1] = { 0 };
        for (unsigned i = 0; i < vp.second.size(); ++i) {
            wbuffer[0] = (unsigned) vp.second[i];
            destfile.write((char*)wbuffer, 1);
        }
    }
    destfile.close();
    delete(exploitState);
    return true;
}


bool FuzzyS2E::getAFLBitmapSHM()
{
    m_aflBitmapSHM = NULL;
    key_t shmkey;
    std::stringstream tracebits_strstream;
    tracebits_strstream << "/tmp/afltracebits/trace_" << m_QEMUPid;
    std::string bitmap_file = tracebits_strstream.str();
    FILE* Pbitmap = fopen(bitmap_file.c_str(), "ab+");
    if (!Pbitmap) {
        s2e()->getDebugStream() << "FuzzyS2E: cannot create trace bitmap file: "
                            << bitmap_file << "\n";
        exit(-1);
    }
    fclose(Pbitmap);

    do {
        if ((shmkey = ftok(bitmap_file.c_str(), 1)) < 0) {
            s2e()->getDebugStream() << "FuzzyS2E: ftok() error: "
                    << strerror(errno) << "\n";
            return false;
        }
        int shm_id;
        try {
            shm_id = shmget(shmkey, AFL_BITMAP_SIZE, IPC_CREAT | 0600);
            if (shm_id < 0) {
                s2e()->getDebugStream() << "FuzzyS2E: shmget() error: "
                        << strerror(errno) << "\n";
                return false;
            }
            void * afl_area_ptr = shmat(shm_id, NULL, 0);
            if (afl_area_ptr == (void*) -1) {
                s2e()->getDebugStream() << "FuzzyS2E: shmat() error: "
                        << strerror(errno) << "\n";
                exit(1);
            }
            m_aflBitmapSHM = (unsigned char*) afl_area_ptr;
            m_findBitMapSHM = true;
            m_shmID = shm_id;
            if (m_verbose) {
                s2e()->getDebugStream() << "FuzzyS2E: Trace bits share memory id is "
                        << shm_id << "\n";
            }
        } catch (...) {
            return false;
        }
    } while (0);
    return true;
}

bool FuzzyS2E::initQemuQueue()
{
    int res;
    if (access(QEMUQUEUE, F_OK) == -1) {
        res = mkfifo(QEMUQUEUE, 0777);
        if (res != 0) {
            s2e()->getDebugStream() << "Could not create fifo " << QEMUQUEUE << ".\n";
            return false;
        }
    }
    m_queueFd = open(QEMUQUEUE, O_WRONLY | O_NONBLOCK);

    if (m_queueFd == -1)
    {
        s2e()->getDebugStream() << "Could not open fifo " << QEMUQUEUE << ".\n";
        return false;
    }
    // after the queue is initialized, write OK to FIFO
    assert(m_QEMUPid);
    char buffer[FIFOBUFFERSIZE + 1];
    memset(buffer, '\0', FIFOBUFFERSIZE + 1);
    sprintf(buffer, "%d|%d|%lu", m_QEMUPid, FAULT_NONE, (uint64_t)0);
    res = write(m_queueFd, buffer, FIFOBUFFERSIZE);
    if (res == -1)
    {
        s2e()->getDebugStream() << "Write error on pipe\n";
        exit(EXIT_FAILURE);
    }
    return true;
}

bool FuzzyS2E::initReadySHM()
{
    void *shm = NULL;
    int shmid;
    shmid = shmget((key_t) READYSHMID, sizeof(uint8_t)*65536, 0666);
    if (shmid == -1) {
        fprintf(stderr, "shmget failed\n");
        return false;
    }
    shm = shmat(shmid, (void*) 0, 0);
    if (shm == (void*) -1) {
        fprintf(stderr, "shmat failed\n");
        return false;
    }
    m_ReadyArray = (uint8_t*) shm;
    return true;
}


void FuzzyS2E::wait_afl_testcase(S2EExecutionState *state)
{
	s2e()->getDebugStream() << "FuzzyS2E: waiting for afl's test case.\n";
	s2e()->getDebugStream().flush();
    cpu_disable_ticks(); // disable guest clock
    char tmp[4];
    char err[128];
    int len;
wait:
    do{
        len = ::read(CTRLPIPE(m_QEMUPid), tmp, 4);
        if(len == -1){
            if(errno == EINTR)
                continue;
            break;
        }else
            break;

    } while(1);
    if (len != 4)
    {
        sprintf(err, "errno.%02d is: %s/n", errno, strerror(errno));
        s2e()->getDebugStream() << "FuzzyS2E: we cannot read pipe, length is " << len << ", error is "<< err << "\n";
        exit(2); // we want block here, why not ?
    }
    if(m_needFilter){

        if (m_useDrill && m_TestcaseFilter->getModeSwitched()) {
            if (tmp[0] == 'n') {
                assert(m_DrillFreqCounter && "Cannot reach zero!!!");
                m_DrillFreqCounter -= 1;
            }
            else if (tmp[0] == 'p')
                m_DrillFreqCounter = m_drillFreq; // reset counter
        }

        if (m_killRState && tmp[0] == 'n')
            m_TestcaseFilter->simpSigStates(m_lastID); //XXX

        bool next_symbex = false;

        if (m_TestcaseFilter->isRedundant(m_filename.c_str(), &next_symbex)) {
            s2e()->getDebugStream() << "FuzzyS2E: capure a redundant testcase.\n";
            report_redundant();// tell afl this is a redundant case and wait again
            goto wait;
        }
    }
    cpu_enable_ticks();
}

void FuzzyS2E::RemoveUnscheduleState(S2EExecutionState *state)
{
    /* Remove the states which are collected by TestcaseFilter */
    assert(m_schedule_states.size() && "FuzzyS2E: Scheduled states collector is empty!");
    auto it = m_schedule_states.begin();
    bool ok = false;
    for (; it != m_schedule_states.end(); it++) {
        if (*it == state){
            m_schedule_states.erase(it);
            ok = true;
            break;
        }

    }
    assert(ok && "invalid state removed");
}

void FuzzyS2E::report_redundant()
{
    char buffer[FIFOBUFFERSIZE + 1];
    memset(buffer, '\0', FIFOBUFFERSIZE + 1);
    sprintf(buffer, "%d|%d|%lu", m_QEMUPid, FAULT_REDUNDANT, uint64_t(0));
    int res = write(m_queueFd, buffer, FIFOBUFFERSIZE);
    if (res == -1)
    {
        s2e()->getDebugStream() << "Write error on pipe, qemu is going to die...\n";
        s2e()->getDebugStream().flush();
        exit(EXIT_FAILURE);
    }
    assert(m_queueFd > 0 && "Haven't seen qemu queue yet?");
    m_ReadyArray[m_QEMUPid] = 1;
}

// Write OK signal to queue to notify AFL that guest is ready (message is qemu's pid).
void FuzzyS2E::tell_afl(S2EExecutionState *state, bool reserveState) // mark this as an atom procedure, i.e. should NOT be interrupted
{
    DECLARE_PLUGINSTATE(FuzzyS2EState, state);
    assert(m_queueFd > 0 && "Haven't seen qemu queue yet?");
    char buffer[FIFOBUFFERSIZE + 1];
    memset(buffer, '\0', FIFOBUFFERSIZE + 1);
    if(!plgState->m_ExecTime){
        s2e()->getDebugStream() << "Cannot get execute time ?\n";
        s2e()->getDebugStream().flush();
        exit(EXIT_FAILURE);
    }
    uint64_t m_ellapsetime = plgState->m_ExecTime->check();
    s2e()->getDebugStream() << "The testing lasts for " << m_ellapsetime << " microseconds.\n";
    sprintf(buffer, "%d|%d|%lu", m_QEMUPid, plgState->m_fault, m_ellapsetime);
    int res = write(m_queueFd, buffer, FIFOBUFFERSIZE);
    if (res == -1)
    {
        s2e()->getDebugStream() << "Write error on pipe, qemu is going to die...\n";
        s2e()->getDebugStream().flush();
        exit(EXIT_FAILURE);
    }
    bool merged = false;
    if (m_needFilter) {
        RemoveUnscheduleState(state);
        if (m_TestcaseFilter->getSigStates().size() < m_TestcaseFilter->getMAXstates() && reserveState)
            merged = m_TestcaseFilter->addSigState(state);
    }
    m_lastID = state->getID();
    assert(!m_ReadyArray[m_QEMUPid] && "I'm free before? ");  //FIXME: bug here
    m_ReadyArray[m_QEMUPid] = 1;
    if (merged)
        s2e()->getExecutor()->terminateStateEarly(*state, "merged states!"); // kill merged state
}

void FuzzyS2E::fork_work_state(S2EExecutionState *state)
{
    klee::Executor::StatePair sp;
    bool oldForkStatus = state->isForkingEnabled();
    state->jumpToSymbolicCpp();
    state->enableForking();

    assert(!state->getID() && "Should come from initial state!");

    if (!m_has_dummy_symb) {
        std::vector<unsigned char> concreteValues;
        unsigned bytes = klee::Expr::getMinBytesForWidth(klee::Expr::Int32);
        for (unsigned i = 0; i < bytes; ++i) {
            concreteValues.push_back(0xFF);
        }
        m_dummy_symb = state->createConcolicValue("dummy_symb_var",
                        klee::Expr::Int32, concreteValues); // we need to create an initial state which can be used to continue execution
        m_has_dummy_symb = true;
    }


    klee::ref<klee::Expr> cond = klee::UleExpr::create(m_dummy_symb,
                klee::ConstantExpr::create(m_current_conditon, klee::Expr::Int32));

    sp = s2e()->getExecutor()->forkCondition(state, cond, true, false);
    S2EExecutionState *ts = static_cast<S2EExecutionState *>(sp.first);
    S2EExecutionState *fs = static_cast<S2EExecutionState *>(sp.second);

    ts->setForking(oldForkStatus);

    /*
     * Enable work state forking only when all of the following conditions are satisfied:
     * 1. Need TestcaseFilter
     * 2. Using drill mode
     * 3. Switched to PF mode
     * 4. Hitting drill sample rate
     */

    if (m_needFilter && m_useDrill && m_TestcaseFilter->getModeSwitched() && !m_DrillFreqCounter)
        fs->setForking(true);
    else
        fs->setForking(false);

    m_current_conditon+=1;

    if (m_needFilter)
        const_arr_id = 0;

    return;
}

void FuzzyS2E::wait_work_state(S2EExecutionState *state)
{
    if(m_schedule_states.size() <= 1)
        return;

    s2e()->getDebugStream() << "Yield seed state.\n";
    state->yield(true);

    //force executor to select another (i.e. work state) state
    state->regs()->write<int>(CPU_OFFSET(exception_index), EXCP_SE);
    throw CpuExitException();
}

void FuzzyS2E::onCustomInstruction(
        S2EExecutionState *state,
        uint64_t operand
        )
{
    if (!OPCODE_CHECK(operand, FUZZCONTROL_OPCODE)) {
        return;
    }

    uint64_t subfunction = OPCODE_GETSUBFUNCTION(operand);

    switch (subfunction) {
        case 0x0: {
            // Guest wants us to wait for AFL's testcase, so let's wait.
            wait_afl_testcase(state);
            break;
        }
        case 0x1: {
            // Guest wants us to notify AFL that it has finished a test
            tell_afl(state);
            break;
        }
        case 0x2: {
            // Guest wants to know whether do we need symbex, do it just once
        	target_ulong need_symbex;
        	if (m_needFilter) {
        	    need_symbex = m_TestcaseFilter->getSigStates().size() < (m_TestcaseFilter->getMAXstates() - 1);
        	    if (!need_symbex) {
        	        if (!m_TestcaseFilter->getModeSwitched())
        	            m_TestcaseFilter->setModeSwitched(true);
        	        s2e()->getDebugStream() << "FuzzyS2E: switch to PF mode because reached maximum states number!\n";
        	    }
        	    if (m_useDrill && m_TestcaseFilter->getModeSwitched() && !m_DrillFreqCounter) {
        	        need_symbex = 1;
        	        m_DrillFreqCounter = m_drillFreq; // reset counter
        	        s2e()->getDebugStream() << "FuzzyS2E: Ready to start Driller!\n";
        	    }
        	}
        	else
        	    need_symbex = 0;
        	state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &need_symbex, sizeof(need_symbex));
        	// Add initial state as a schedule state
        	if (!m_schedule_states.size() && !state->getID())
        	    m_schedule_states.push_back(state);

            break;
        }
        case 0x3: {
            // Guest wants to fork a state which is used to perform testing.
        	fork_work_state(state);
        	break;
        }
        case 0x4: {
            // Guest wants to be scheduled to the forked work state.
            wait_work_state(state);
        	break;
        }
        case 0x5: {
            // Guests gives the target pid
            if (m_mainPid)
                break;
            else {
                bool ok;
                target_ulong target_pid = 0;
                ok = state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]),
                                                         &target_pid, sizeof(target_pid));
                m_mainPid = target_pid;
                assert(m_mainPid);
                s2e()->getDebugStream() << "FuzzyS2E: target pid is " << m_mainPid << ".\n";
                break;
            }
        }
        case 0x6: {
            // Guest wants to know whether do we need to parse modules information
            target_ulong need_info = m_parsedModInfo ? 0 : 1;
            state->writeCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &need_info, sizeof(need_info));
            break;
        }
        default: {
            s2e()->getWarningsStream(state) << "Invalid FuzzyS2E opcode "
                    << hexval(operand) << '\n';
            break;
        }
    }

}

/**********************************************************/
/**********************************************************/
/**********************************************************/

void FuzzyS2E::handleModuleLoad(S2EExecutionState *state, const S2E_FUZZYS2EMONITOR_MODULE_LOAD &m)
{
    //if (m_parsedModInfo)
    //    return;
    ModuleDescriptor module;
    std::string name, path;

    bool ret = true;

    ret &= state->mem()->readString(m.name, name);
    if (m.path) {
        ret &= state->mem()->readString(m.path, path);
    }

    if (!ret) {
        getWarningsStream(state) << "Could not read module name or path\n";
        return;
    }

    module.Name = name;
    module.Path = path;
    module.AddressSpace = state->regs()->getPageDir();
    module.Pid = m.pid;
    module.EntryPoint = m.entryPoint;
    module.LoadBase = m.loadBase;
    module.NativeBase = m.nativeBase;
    module.Size = m.size;

    s2e()->getDebugStream() << module << "\n";
    if (m_mainModule == module.Name) {
        m_mainModuleDes = module;
        if (m_needFilter)
            m_TestcaseFilter->setMainImage(module.LoadBase, module.Size);
        m_parsedModInfo = true;
    }

}

void FuzzyS2E::handleOpcodeInvocation(S2EExecutionState *state,
                            uint64_t guestDataPtr,
                            uint64_t guestDataSize)
{
    S2E_FUZZYS2EMONITOR_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) <<
                "FuzzyS2E: mismatched S2E_RAWMONITOR_COMMAND size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) <<
                "FuzzyS2E: could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case ONMODULE_LOAD: {
            handleModuleLoad(state, command.ModuleLoad);
        } break;

        default: {
            getWarningsStream(state) <<
                    "FuzzyS2E: unknown command " << command.Command << "\n";
        } break;
    }

}


/*
 * update bitmap. Taken from AFL
 */
bool FuzzyS2EState::updateAFLBitmapSHM(unsigned char* AflBitmap,
        uint32_t curBBpc)
{
    uint32_t cur_location = (curBBpc >> 4) ^ (curBBpc << 8);
    cur_location &= AFL_BITMAP_SIZE - 1;
    if (cur_location >= AFL_BITMAP_SIZE)
        return false;
    AflBitmap[cur_location ^ m_prev_loc]++;
    m_prev_loc = cur_location >> 1;
    return true;
}

FuzzyS2EState::FuzzyS2EState()
{
    m_plugin = NULL;
    m_state = NULL;
    m_prev_loc = 0;
    m_ExecTime = new klee::WallTimer();
    m_fault = FAULT_NONE;
}

FuzzyS2EState::~FuzzyS2EState()
{
    if (m_ExecTime)
        delete m_ExecTime;
}

PluginState *FuzzyS2EState::clone() const
{
    return new FuzzyS2EState();
}

PluginState *FuzzyS2EState::factory(Plugin *p, S2EExecutionState *s)
{
    FuzzyS2EState *ret = new FuzzyS2EState();
    return ret;
}

} /* namespace plugin */
} /* namespace s2e */

