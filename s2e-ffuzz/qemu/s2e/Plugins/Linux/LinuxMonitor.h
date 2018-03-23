///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_LinuxMonitor_H
#define S2E_PLUGINS_LinuxMonitor_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/Plugins/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>
#include <vmi/Vmi.h>
#include <vmi/ExecutableFile.h>
#include <vmi/ElfDwarf.h>
#include <llvm/Support/Path.h>

namespace s2e {
namespace plugins {

class LinuxMonitor : public OSMonitor, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN
public:
    LinuxMonitor(S2E* s2e): OSMonitor(s2e) {}

    void initialize();

private:
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                               TranslationBlock *tb,
                               uint64_t pc);

    void onFirstInstruction(S2EExecutionState* state, uint64_t pc);
    void onStartThread(S2EExecutionState* state, uint64_t pc);
    void onProfileTaskExit(S2EExecutionState* state, uint64_t pc);
    void onForceSigInfo(S2EExecutionState* state, uint64_t pc);

    sigc::connection m_onTranslateInstructionConnection;
    sigc::connection m_onFirstInstructionConnection;
    sigc::connection m_onStartThreadConnection;
    sigc::connection m_onProfileTaskExitConnection;
    sigc::connection m_onForceSigInfoConnection;
    unsigned m_connectionCount;

    vmi::ExecutableFile *m_vmlinux;
    vmi::Vmi *m_vmi;

    uint64_t m_tasks_next_offset;
    uint64_t m_kernelStart;
    uint64_t m_kernelStackSize;

    //Addresses of functions
    uint64_t m_profile_task_exit_address;
    uint64_t m_start_thread_address;
    uint64_t m_force_sig_info_address;

    //Address of the list of tasks
    uint64_t m_init_task_address;

    bool m_instrumentFirstInstruction;

    void notifyKernelLoad(S2EExecutionState *state);
    bool notifyLoad(S2EExecutionState *state, uint64_t taskAddress);
    bool notifyLoadForAllTasks(S2EExecutionState *state);
    bool extractTaskInfo(S2EExecutionState *state, uint64_t taskAddress, ModuleDescriptor &result);

    bool getPtRegs(S2EExecutionState *state, uint64_t taskPtr, uint64_t *ptregs);
    bool getCurrentTask(S2EExecutionState *state, uint64_t *taskPtr);
public:


    sigc::signal<void,
       S2EExecutionState*,
       uint64_t /* pointer to task_struct */,
       uint64_t /* pointer to siginfo */,
       unsigned /* signal number */,
       bool /* isHandled */,
       const ModuleDescriptor &
    >onSignal;

    virtual bool getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I);
    virtual bool getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E);
    virtual bool getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R);
    virtual bool isKernelAddress(uint64_t pc) const;
    virtual uint64_t getAddressSpace(S2EExecutionState *s, uint64_t pc);
    virtual bool getCurrentStack(S2EExecutionState *s, uint64_t *base, uint64_t *size);

    bool getFaultAddress(S2EExecutionState *state, uint64_t siginfo_ptr, uint64_t *address);

    //reg is a QEMU register identifier (e.g., R_EAX...)
    bool getRegisterAtFault(S2EExecutionState *state, uint64_t task_ptr, const char *reg_name, uint64_t *value);

    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);

    uint64_t getPid(S2EExecutionState *state, uint64_t pc) {
        return getAddressSpace(state, pc);
    }
    uint64_t getPid(S2EExecutionState *state) {
        return getPid(state, state->getPc());
    }
    uint64_t getTid(S2EExecutionState *state) {
        assert(false && "Not implemented");
        return getPid(state);
    }

    bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) { return false; }
};

enum LinuxMonitorOps {
    MODULE_LOAD32 = 0, MODULE_UNLOAD32
};

struct LinuxMonitorOpcode32 {
    uint32_t operation;  //LinuxMonitorOps
    uint32_t moduleNamePtr;
    uint64_t moduleStart;
    uint64_t moduleEnd;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LinuxMonitor_H
