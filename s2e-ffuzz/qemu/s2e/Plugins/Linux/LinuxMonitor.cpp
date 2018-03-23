///
/// Copyright (C) 2012-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/cpu.h>

#include <llvm/Config/config.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

#include "LinuxMonitor.h"
#include <s2e/Plugins/Vmi.h>


namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LinuxMonitor, "LinuxMonitor S2E plugin", "Interceptor", "Vmi", "BaseInstructions");


void LinuxMonitor::initialize()
{
    bool ok;
    ConfigFile *cfg = s2e()->getConfig();

    std::string vmlinux = cfg->getString(getConfigKey() + ".kernel", "", &ok);
    if (!ok) {
        getWarningsStream() << "LinuxMonitor: "
                << "Please assign the name of the kernel image to "
                << getConfigKey() << ".kernel\n";
        exit(-1);
    }

    Vmi* vmiPlugin = static_cast<Vmi*>(s2e()->getPlugin("Vmi"));
    assert(vmiPlugin);

    Vmi::ExeData data;
    if (!vmiPlugin->get(vmlinux, data)) {
        exit(-1);
    }

    m_vmlinux = data.execFile;
    m_vmi = data.vmi;

    ok = true;
    ok &= m_vmlinux->getSymbolAddress("init_task", &m_init_task_address);
    ok &= m_vmlinux->getSymbolAddress("do_exit", &m_profile_task_exit_address);
    ok &= m_vmlinux->getSymbolAddress("start_thread", &m_start_thread_address);
    ok &= m_vmlinux->getSymbolAddress("send_signal", &m_force_sig_info_address);

    if (!ok) {
        getWarningsStream() << "LinuxMonitor: " <<
                "Could not find addresses of init_task, profile_task_exit, and/or start_thread."
                " Make sure the kernel parameter specifies a valid Linux image with debug info.\n";
        exit(-1);
    }

    //Verify that we have all the required types in the debug info
    if (!m_vmi->get("task_struct")) {
        getWarningsStream() << "LinuxMonitor: " <<
                "Could not find type info for task_struct in " << vmlinux << '\n'<<
                "Check that you compiled your kernel with full type information (section .debug_pubtypes).\n";
        exit(-1);
    }

    ok = m_vmi->getOffset("task_struct", "tasks.next", m_tasks_next_offset);
    assert(ok);

    m_onTranslateInstructionConnection =
            s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                    sigc::mem_fun(*this, &LinuxMonitor::onTranslateBlockStart));

    m_connectionCount = 0;
    m_instrumentFirstInstruction = true;
    m_kernelStart = 0xc0000000;
    m_kernelStackSize = 0x2000;
}


void LinuxMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                          TranslationBlock *tb,  uint64_t pc)
{
    if (m_instrumentFirstInstruction) {
        getDebugStream(state) << "LinuxMonitor: Instrumenting first instruction\n";
        m_onFirstInstructionConnection =
                signal->connect(sigc::mem_fun(*this, &LinuxMonitor::onFirstInstruction));
        m_instrumentFirstInstruction = false;
    } else if (pc == m_profile_task_exit_address) {
        getDebugStream(state) << "LinuxMonitor: Instrumenting m_profile_task_exit_address\n";
        m_onProfileTaskExitConnection =
                signal->connect(sigc::mem_fun(*this, &LinuxMonitor::onProfileTaskExit));

    } else if (pc == m_start_thread_address) {
        getDebugStream(state) << "LinuxMonitor: Instrumenting m_start_thread_address\n";
        m_onStartThreadConnection =
                signal->connect(sigc::mem_fun(*this, &LinuxMonitor::onStartThread));

    } else if (pc == m_force_sig_info_address) {
        getDebugStream(state) << "LinuxMonitor: Instrumenting m_force_sig_info_address\n";
        m_onForceSigInfoConnection =
                signal->connect(sigc::mem_fun(*this, &LinuxMonitor::onForceSigInfo));

    }
}

void LinuxMonitor::onFirstInstruction(S2EExecutionState* state, uint64_t pc)
{
    m_onFirstInstructionConnection.disconnect();
    notifyLoadForAllTasks(state);
}

void LinuxMonitor::onForceSigInfo(S2EExecutionState* state, uint64_t pc)
{
    //XXX: Use VMI to fetch parameters
    //XXX: the following may break if kernel is compiled with different switches.
    bool ok = true;
    uint32_t sig, info, tsk;

    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EAX]), &sig, 4);

    //XXX: don't capture all the signals for now.
    if (sig > 31) {
        return;
    }

    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_EDX]), &info, 4);
    ok &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[R_ECX]), &tsk, 4);

    ModuleDescriptor module;
    if (!extractTaskInfo(state, tsk, module)) {
        return;
    }

    uint32_t signalHandler;
    std::stringstream ss;
    ss << "sighand->action[" << sig - 1 << "]->sa.sa_handler";
    ok = m_vmi->get("task_struct", ss.str(), tsk, &signalHandler, state);
    if (!ok) {
        getWarningsStream(state) << "LinuxMonitor: could not access field " << ss.str() << "\n";
        return;
    }

    //From the Linux kernel:
    //#define SIG_DFL	((__force __sighandler_t)0)	/* default signal handling */
    //#define SIG_IGN	((__force __sighandler_t)1)	/* ignore signal */
    //#define SIG_ERR	((__force __sighandler_t)-1)	/* error return from signal */
    bool handled = signalHandler != 0;

    if (!handled) {
        uint64_t eip;
        getRegisterAtFault(state, tsk, "ip", &eip);

        getDebugStream(state) << "LinuxMonitor: Unhandled signal caught! "
                << "Module " << module.Name << " signal " << hexval(sig) << " at pc=" << hexval(eip) << "\n";
    } else {
        uint64_t eip = 0;
        getDebugStream(state) << "LinuxMonitor: Handled signal caught! "
                << "Module " << module.Name << " signal " << hexval(sig) << " at pc=" << hexval(eip) << "\n";
    }

    onSignal.emit(state, tsk, info, sig, handled, module);
    return;
}

bool LinuxMonitor::getCurrentTask(S2EExecutionState *state, uint64_t *taskPtr)
{
    //Determine the current task
    uint32_t currentThreadInfo = state->getSp() & 0xffffe000;

    uint32_t task;
    if (!m_vmi->get("thread_info", "task", currentThreadInfo, &task, state)) {
        return false;
    }

    *taskPtr = task;
    return true;
}

/**
 * Hooks void start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
 */
void LinuxMonitor::onStartThread(S2EExecutionState* state, uint64_t pc)
{
    getDebugStream(state) << "LinuxMonitor: starting thread\n";

    uint64_t taskPtr;
    if (!getCurrentTask(state, &taskPtr)) {
        return;
    }

    notifyLoad(state, taskPtr);
}

void LinuxMonitor::onProfileTaskExit(S2EExecutionState* state, uint64_t pc)
{
    uint64_t taskPtr;
    if (!getCurrentTask(state, &taskPtr)) {
        return;
    }

    ModuleDescriptor md;
    if (!extractTaskInfo(state, taskPtr, md)) {
        return;
    }

    getDebugStream(state) << "LinuxMonitor: exiting task " << md.Name
            << " as=" << hexval(md.AddressSpace) << "\n";


    onProcessUnload.emit(state, md.AddressSpace, 0);
}



bool LinuxMonitor::getFaultAddress(S2EExecutionState *state, uint64_t siginfo_ptr, uint64_t *address)
{
    uint32_t fault_addr = 0;
    if (!m_vmi->get("siginfo_t", "_sifields._sigfault._addr", siginfo_ptr, &fault_addr, state)) {
        getDebugStream(state) << "LinuxMonitor: could not read siginfo_t addr field\n";
        return false;
    }

    *address = fault_addr;
    return true;
}

bool LinuxMonitor::getRegisterAtFault(S2EExecutionState *state, uint64_t task_ptr, const char *reg_name, uint64_t *value)
{
    uint64_t regs = 0;
    if (!getPtRegs(state, task_ptr, &regs)) {
        return false;
    }


    uint32_t regval;
    if (!m_vmi->get("pt_regs", reg_name, regs, &regval, state)) {
        return false;
    }

    *value = regval;
    return true;
}

/**
 * Get a pointer to the register set saved when entering an exception handler.
 * Emulates the task_pt_regs macro.
 */
bool LinuxMonitor::getPtRegs(S2EExecutionState *state, uint64_t taskPtr, uint64_t *ptregs)
{
    bool ok = true;
    uint32_t task_stack_ptr;
    ok &= m_vmi->get("task_struct", "stack", taskPtr, &task_stack_ptr, state);
    if (!ok) {
        return false;
    }

    task_stack_ptr += m_kernelStackSize;
    task_stack_ptr -= 8;

    const vmi::VmiType *pt_regs_t = m_vmi->get("pt_regs");
    if (!pt_regs_t) {
        return false;
    }

    task_stack_ptr -= pt_regs_t->getSize();

    *ptregs = task_stack_ptr;

    return true;
}

bool LinuxMonitor::extractTaskInfo(S2EExecutionState *state, uint64_t taskPtr, ModuleDescriptor &result)
{
    bool ok = true;
    ok &= m_vmi->getString("task_struct", "comm", taskPtr, result.Name, state);

    uint32_t mmPtr;
    ok &= m_vmi->get("task_struct", "mm", taskPtr, &mmPtr, state);

    uint32_t start_code, end_code;
    ok &= m_vmi->get("mm_struct", "start_code", mmPtr, &start_code, state);
    ok &= m_vmi->get("mm_struct", "end_code", mmPtr, &end_code, state);

    //XXX: what about other sections of the binary??
    //XXX: what about relocatable apps, ASLR?
    //XXX: what about the program entry point?
    result.LoadBase = start_code;
    result.NativeBase = start_code;
    result.Size = end_code - start_code;

    uint32_t pgd;
    ok &= m_vmi->get("mm_struct", "pgd", mmPtr, &pgd, state);
    result.AddressSpace = state->getPhysicalAddress(pgd);

    return ok;
}

void LinuxMonitor::notifyKernelLoad(S2EExecutionState *state)
{
    ModuleDescriptor md;
    md.Name = "vmlinux";
    md.NativeBase = m_kernelStart;
    md.LoadBase = m_kernelStart;
    md.Size = m_vmlinux->getImageSize();
    md.AddressSpace = 0;
    onModuleLoad.emit(state, md);
}

bool LinuxMonitor::notifyLoad(S2EExecutionState *state, uint64_t taskAddress)
{
    bool ok = true;
    uint32_t pid, tgid;
    ModuleDescriptor md;

    ok &= m_vmi->get("task_struct", "pid", taskAddress, &pid, state);
    ok &= m_vmi->get("task_struct", "tgid", taskAddress, &tgid, state);

    //If pid == tgid, it's a process. Otherwise it is a thread.
    if (ok && (pid == tgid) &&  extractTaskInfo(state, taskAddress, md)) {
        getDebugStream(state) << md << "\n";
        onModuleLoad.emit(state, md);
        return true;
    }

    return false;
}

bool LinuxMonitor::notifyLoadForAllTasks(S2EExecutionState *state)
{
    uint32_t currentTaskPtr = m_init_task_address;
    uint32_t firstTaskPtr = m_init_task_address;
    uint32_t nextTaskPtr;

    notifyKernelLoad(state);

    //Skip the swapper task (which is the first task in the list)
    if (!m_vmi->get("task_struct", "tasks.next", currentTaskPtr, &currentTaskPtr, state)) {
        return false;
    }
    currentTaskPtr -= m_tasks_next_offset;

    do  {
        if (!m_vmi->get("task_struct", "tasks.next", currentTaskPtr, &nextTaskPtr, state)) {
            return false;
        }

        notifyLoad(state, currentTaskPtr);

        currentTaskPtr = nextTaskPtr - m_tasks_next_offset;
    } while (currentTaskPtr != firstTaskPtr);

    return true;
}


void LinuxMonitor::handleOpcodeInvocation(S2EExecutionState *state,
                                    uint64_t guestDataPtr,
                                    uint64_t guestDataSize)
{
    LinuxMonitorOpcode32 opcode;
    if (!state->readMemoryConcrete(guestDataPtr, &opcode, sizeof(opcode))) {
        getWarningsStream(state) << "LinuxMonitor: could not read opcode data\n";
        return;
    }

    std::string module;
    if (!state->mem()->readString(opcode.moduleNamePtr, module)) {
        getWarningsStream(state)
                << "Linux monitor: handleOpcodeInvocation could not read module name\n";
        return;
    }

    module = llvm::sys::path::filename(module);


    ModuleDescriptor md;
    md.Name = module;
    md.LoadBase = opcode.moduleStart;
    md.NativeBase = 0; //opcode.moduleStart; //XXXX
    md.Size = opcode.moduleEnd - opcode.moduleStart;
    md.AddressSpace = state->getPageDir();

    if (opcode.operation == MODULE_LOAD32) {
        getDebugStream(state) << "LinuxMonitor: loading module " << module << " at "
                << hexval(md.LoadBase) <<  " size=" << hexval(md.Size) << "\n";
        onModuleLoad.emit(state, md);
    } else {
        assert(false && "Module unload not implemented yet");
    }
}

bool LinuxMonitor::getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I)
{
    return false;
}

bool LinuxMonitor::getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E)
{
    return false;
}

bool LinuxMonitor::getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R)
{
    return false;
}

bool LinuxMonitor::isKernelAddress(uint64_t pc) const
{
    return pc >= m_kernelStart;
}

uint64_t LinuxMonitor::getAddressSpace(S2EExecutionState *s, uint64_t pc)
{
    if (pc >= m_kernelStart) {
        return 0;
    } else {
        return s->getPageDir();
    }
}

bool LinuxMonitor::getCurrentStack(S2EExecutionState *s, uint64_t *base, uint64_t *size)
{
    return false;
}

} // namespace plugins
} // namespace s2e
