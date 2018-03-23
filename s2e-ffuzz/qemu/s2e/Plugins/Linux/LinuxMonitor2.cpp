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
#include "config.h"
#include "qemu-common.h"
extern CPUX86State *env;
}

#include "LinuxMonitor2.h"

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/Searchers/SeedSearcher.h>

#include <s2e/Plugins/ProcessExecutionDetector.h>

#include <klee/Solver.h>
#include <klee/util/ExprTemplates.h>

#include <string>
#include <iostream>

using namespace klee;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxMonitor2, "LinuxMonitor 2nd version S2E plugin", "Interceptor", "BaseInstructions", "Vmi");


void LinuxMonitor2::initialize()
{
    m_kernelStart = 0xc0000000;
    m_base = s2e()->getPlugin<BaseInstructions>();
    // XXX: fix this circular dependency.
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_cfg = s2e()->getConfig();

    m_terminateOnSegfault   = m_cfg->getBool(getConfigKey() + ".terminateOnSegfault", true);
    m_terminateOnDivebyzero = m_cfg->getBool(getConfigKey() + ".terminateOnDivebyzero", true);
    m_updatePidexpensive    = m_cfg->getBool(getConfigKey() + ".updatePidexpensive", false);
}

class LinuxMonitor2State: public PluginState {
public:
    //HACK: update when process create and exit because updating
    //    with kernel task schedule signal is expensive
    std::map<uint64_t /* pid */, ModuleDescriptor /* module */> m_modulesByPid;

    virtual LinuxMonitor2State* clone() const {
        LinuxMonitor2State *ret = new LinuxMonitor2State(*this);
        return ret;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new LinuxMonitor2State();
    }

    virtual ~LinuxMonitor2State() {

    }
};

bool LinuxMonitor2::getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I)
{
    return false;
}

bool LinuxMonitor2::getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E)
{
    return false;
}

bool LinuxMonitor2::getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R)
{
    return false;
}

bool LinuxMonitor2::isKernelAddress(uint64_t pc) const
{
    return pc >= m_kernelStart;
}

uint64_t LinuxMonitor2::getAddressSpace(S2EExecutionState *s, uint64_t pc)
{
    if (pc >= m_kernelStart) {
        return 0;
    } else {
        return s->getPageDir();
    }
}

bool LinuxMonitor2::getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size)
{
// TODO: get real stack size from process memory map
#define STACK_SIZE                  ( 16 * 1024 * 1024 )

    ModuleExecutionDetector *detector;
    const ModuleDescriptor *module;

    detector = (ModuleExecutionDetector*) s2e()->getPlugin("ModuleExecutionDetector");
    assert(detector);

    module = detector->getCurrentDescriptor(state);
    if (!module) {
        return false;
    }

    *base = module->StackTop - STACK_SIZE;
    *size = STACK_SIZE;

    // 'pop' instruction can be executed when ESP is set to STACK_TOP
    *size += state->getPointerSize() + 1;

    return true;
}

void LinuxMonitor2::handleElfBinaryLoad(S2EExecutionState *state, const S2E_LINUXMON_COMMAND_ELFBINARY_LOAD &p)
{
    static bool loaded = false;

    if (!loaded) {
        onMonitorLoad.emit(state);
        loaded = true;
    }

    std::string processPath(p.process_path, strnlen(p.process_path, sizeof(p.process_path)));

    getWarningsStream(state) << "ElfBinaryLoad: " << processPath
                             << " entry_point: " << hexval(p.entry_point)
                             << " pid: " << hexval(p.process_id)
                             << " start_code: " << hexval(p.start_code)
                             << " end_code: " << hexval(p.end_code)
                             << " start_data: " << hexval(p.start_data)
                             << " end_data: " << hexval(p.end_data)
                             << " start_stack: " << hexval(p.start_stack)
                             << "\n";

    llvm::StringRef file(processPath);

    onProcessLoad.emit(state, state->getPageDir(), p.process_id, llvm::sys::path::stem(file));

    ModuleDescriptor mod;
    mod.Name = llvm::sys::path::stem(file);
    mod.Path = file.str();
    mod.AddressSpace = state->getPageDir();
    mod.Pid = p.process_id;
    mod.LoadBase = p.start_code;
    mod.NativeBase = p.start_code;
    mod.Size = p.end_data - p.start_code;
    mod.EntryPoint = p.entry_point;
    mod.DataBase = p.start_data;
    mod.DataSize = p.end_data - p.start_data;
    mod.StackTop = p.start_stack;

    getDebugStream(state) << mod << "\n";

    onModuleLoad.emit(state, mod);

    DECLARE_PLUGINSTATE(LinuxMonitor2State, state);
    plgState->m_modulesByPid[mod.Pid] = mod; // insert to module collector
}

void LinuxMonitor2::handleTaskExit(S2EExecutionState *s, const S2E_LINUXMON_COMMAND &p)
{
    onProcessUnload.emit(s, s->getPageDir() , p.currentPid);
    DECLARE_PLUGINSTATE(LinuxMonitor2State, s);
    auto it = plgState->m_modulesByPid.find(p.currentPid);
    if (it == plgState->m_modulesByPid.end()) {
        return; // not find and forget it
    }
    ModuleDescriptor mod = (*it).second;
    s2e()->getDebugStream() << "Removing task (pid: " << p.currentPid << ", cr3: " << mod.AddressSpace << ") record from collector.\n";
    plgState->m_modulesByPid.erase(it);
    return;
}

/*
#define GETMODDES(_mod, p) \
    do{                     \
        _mod.Name = ::string(p.process_path); \
        _mod.Path = ::string(p.process_path);  \
        _mod.AddressSpace = p.page_dir;    \
        _mod.Pid = p.pid;   \
        _mod.LoadBase = p.start_code;     \
        _mod.NativeBase = p.start_code;    \
        _mod.Size = p.end_data - p.start_code;    \
        _mod.EntryPoint = p.entry_point;    \
        _mod.DataBase = p.start_data;    \
        _mod.DataSize = p.end_data - p.start_data;   \
        _mod.StackTop = p.start_stack;    \
    } while(0)
*/
void LinuxMonitor2::handleTaskSwitch(S2EExecutionState *s, const S2E_LINUXMON_COMMAND &p)
{
    //ModuleDescriptor prev_mod, next_mod;
   // GETMODDES(prev_mod, p.TaskSwitch.pre_mod);
    //GETMODDES(next_mod, p.TaskSwitch.nxt_mod);

    return;
}


#define THREAD_SIZE_ORDER   1
#define PAGE_SHIFT          12
#define PAGE_SIZE           (1UL << PAGE_SHIFT)
#define THREAD_SIZE         (PAGE_SIZE << THREAD_SIZE_ORDER)

uint64_t LinuxMonitor2::getPid(S2EExecutionState *state, uint64_t pc)
{
    uint64_t esp0_addr = env->tr.base + 4;
    target_ulong esp0;
    if (!state->mem()->readMemoryConcrete(esp0_addr, &esp0, sizeof(esp0))) {
        return -1;
    }

    uint64_t current_thread_info = esp0 & ~(THREAD_SIZE - 1);
    target_ulong task_ptr;

    if (!state->mem()->readMemoryConcrete(current_thread_info, &task_ptr, sizeof(task_ptr))) {
        return -1;
    }

    target_ulong pid;
    if (!state->mem()->readMemoryConcrete(task_ptr + 548, &pid, sizeof(pid))) { // hard-coded offset
        return -1;
    }

    return pid;
}

bool LinuxMonitor2::getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name)
{
    DECLARE_PLUGINSTATE_CONST(LinuxMonitor2State, state);
    auto it = plgState->m_modulesByPid.find(pid);
    if (it == plgState->m_modulesByPid.end()) {
        return false;
    }

    name = (*it).second.Name;
    return true;
}

bool LinuxMonitor2::verifyCustomInstruction(S2EExecutionState *state,
                                    uint64_t guestDataPtr,
                                    uint64_t guestDataSize,
                                    S2E_LINUXMON_COMMAND& command,
                                    std::ostringstream& symbolicBytes)
{
    s2e_assert(state, guestDataSize == sizeof(command),
            "Invalid command size " << guestDataSize << " != " << sizeof(command)
            << " from pagedir=" << hexval(state->getPageDir()) << " pc=" << hexval(state->getPc()));

    for (unsigned i = 0; i < sizeof(command); ++i) {
        ref<Expr> t = state->readMemory8(guestDataPtr + i);
        if (!t.isNull() && !isa<ConstantExpr>(t)) {
            symbolicBytes << "  " << hexval(i, 2) << "\n";
        }
    }

    if (symbolicBytes.str().length()) {
        getWarningsStream(state) << "Command has symbolic bytes at\n" << symbolicBytes.str();
    }

    bool ok = state->mem()->readMemoryConcrete(guestDataPtr, &command, sizeof(command));
    s2e_assert(state, ok, "Failed to read memory");

    if (command.version != S2E_LINUXMON_COMMAND_VERSION) {
        std::ostringstream os;
        for (unsigned i = 0; i < sizeof(command); i++) {
            os << hexval(((uint8_t *) &command)[i]) << " ";
        }
        getWarningsStream(state) << "Command bytes: " << os.str() << "\n";

        s2e_assert(state, false,
                "Invalid command version " << hexval(command.version) << " != " << hexval(S2E_LINUXMON_COMMAND_VERSION)
                << " from pagedir=" << hexval(state->getPageDir()) << " pc=" << hexval(state->getPc()));
    }
    return true;
}

void LinuxMonitor2::handleOpcodeInvocation(S2EExecutionState *state,
                                    uint64_t guestDataPtr,
                                    uint64_t guestDataSize)
{
    S2E_LINUXMON_COMMAND command;
    std::ostringstream symbolicBytes;

    if(!verifyCustomInstruction(state, guestDataPtr, guestDataSize, command, symbolicBytes))
        return;

    std::string currentName(command.currentName, strnlen(command.currentName, sizeof(command.currentName)));

    onCustomInstuction.emit(state, command, false);

    switch (command.Command) {
        case SEGMENT_FAULT: {
            getWarningsStream(state) << "received segfault"
                                     << " type=" << command.SegmentFault.fault
                                     << " pagedir=" << hexval(state->getPageDir())
                                     << " pid=" << hexval(command.currentPid)
                                     << " pc=" << hexval(command.SegmentFault.pc)
                                     << " addr=" << hexval(command.SegmentFault.address)
                                     << " name=" << currentName << "\n";

            // Dont switch state until it finishes and gets killed by bootstrap
            // Need to print a message here to avoid confusion and needless debugging,
            // wondering why the searcher doesn't work anymore.
            getDebugStream(state) << "Blocking searcher until state is terminated\n";
            state->setStateSwitchForbidden(true);

            state->disassemble(getDebugStream(state), command.SegmentFault.pc, 256);

            onSegmentFault.emit(state, command.currentPid, command.SegmentFault.pc);

            if (m_terminateOnSegfault) {
                getDebugStream(state) << "Terminating state: received segment fault\n";
                s2e()->getExecutor()->terminateStateEarly(*state, "Segment fault");
            }
        } break;

        case ELFBINARY_LOAD: {
            getDebugStream(state) << "LinuxMonitor2: Detect elf binary load for pid: " << command.currentPid <<
                    " file: " << command.currentName << "\n";
            handleElfBinaryLoad(state, command.ElfBinaryLoad);
        } break;

        case LIBRARY_LOAD: {
            //
        } break;

        case DIVIDE_BY_ZERO: {
            getDebugStream(state) << "LinuxMonitor2: Detect divide by zero for pid: " << command.currentPid <<
                        " file: " << command.currentName << "\n";
            getDebugStream(state) << "Current pid is " << getPid(state) << ".\n";
            getDebugStream(state) << "Blocking searcher until state is terminated\n";
            state->setStateSwitchForbidden(true);
            onDividebyZero.emit(state, command.currentPid, command.DividebyZero.fault_pc, (command.DividebyZero.sig_code == FPE_FLTDIV));
            if (m_terminateOnDivebyzero) {
                getDebugStream(state) << "Terminating state: received divide by zero\n";
                s2e()->getExecutor()->terminateStateEarly(*state, "Divide by zero");
            }

        } break;

        case TASK_EXIT: {
            getDebugStream(state) << "LinuxMonitor2: Detect task exit for pid: " << command.currentPid <<
                        " file: " << command.currentName << "\n";
            handleTaskExit(state, command);
        } break;

        case TASK_SWITCH: {
        if (m_updatePidexpensive) {
            getDebugStream(state)
                    << "LinuxMonitor2: Detect task switch from pid: "
                    << command.currentPid << " to pid: "
                    << command.TaskSwitch.nxt_mod.pid << "\n";
            handleTaskSwitch(state, command);
        }
        } break;
    }

    onCustomInstuction.emit(state, command, true);
}

} // namespace plugins
} // namespace s2e
