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

#ifndef S2E_PLUGINS_LINUX_MONITOR_2_H
#define S2E_PLUGINS_LINUX_MONITOR_2_H

#include <s2e/Plugin.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/BaseInstructions.h>
#include <s2e/Plugins/Vmi.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ADT/StringRef.h>

namespace s2e {
namespace plugins {

#define S2E_LINUXMON_COMMAND_VERSION 0x201611031025ULL // date +%Y%m%d%H%M

enum S2E_LINUXMON_COMMANDS {
    SEGMENT_FAULT,
    ELFBINARY_LOAD,
    LIBRARY_LOAD,
    DIVIDE_BY_ZERO,
    TASK_EXIT,
    TASK_SWITCH
};

struct S2E_LINUXMON_COMMAND_ELFBINARY_LOAD {
    uint64_t process_id;

    uint64_t entry_point;

    uint64_t header;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    uint64_t start_stack;

    char process_path[128]; // not NULL terminated
} __attribute__((packed));


struct S2E_LINUXMON_COMMAND_SEGMENT_FAULT {
    uint64_t pc;
    uint64_t address;
    uint64_t fault;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_LIBRARY_LOAD {
    char library_path[128]; // not NULL terminated
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_DIVIDE_BY_ZERO {
    uint64_t fault_pc;
    uint64_t sig_code;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND_TASK_EXIT {
    uint64_t code;
} __attribute__((packed));

typedef struct _surMod {
    uint64_t pid;
    uint64_t entry_point;
    uint64_t header;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    uint64_t start_stack;
    uint64_t page_dir;
    char     process_path[128];
} __attribute__((packed)) surMod_t;

struct S2E_LINUXMON_COMMAND_TASK_SWITCH {
    surMod_t pre_mod;
    surMod_t nxt_mod;
} __attribute__((packed));

struct S2E_LINUXMON_COMMAND {
    uint64_t version;
    enum S2E_LINUXMON_COMMANDS Command;
    uint64_t currentPid;
    union {
        struct S2E_LINUXMON_COMMAND_ELFBINARY_LOAD ElfBinaryLoad;
        struct S2E_LINUXMON_COMMAND_LIBRARY_LOAD LibraryLoad;
        struct S2E_LINUXMON_COMMAND_SEGMENT_FAULT SegmentFault;
        struct S2E_LINUXMON_COMMAND_DIVIDE_BY_ZERO DividebyZero;
        struct S2E_LINUXMON_COMMAND_TASK_EXIT TaskExit;
        struct S2E_LINUXMON_COMMAND_TASK_SWITCH TaskSwitch;
    };
    char currentName[32]; // not NULL terminated
} __attribute__((packed));


template<typename T> T& operator<<(T &stream, const S2E_LINUXMON_COMMANDS &c) {
    switch(c) {
        case SEGMENT_FAULT: stream << "SEGMENT_FAULT"; break;
        case ELFBINARY_LOAD: stream << "ELFBINARY_LOAD"; break;
        case LIBRARY_LOAD: stream << "LIBRARY_LOAD"; break;
        case DIVIDE_BY_ZERO: stream << "DIVIDE_BY_ZERO"; break;
        case TASK_EXIT: stream << "TASK_EXIT"; break;
        case TASK_SWITCH: stream << "TASK_SWITCH"; break;
        default: stream << "INVALID(" << (int) c << ")"; break;
    }
    return stream;
}

class LinuxMonitor2State;
class ProcessExecutionDetector;

class LinuxMonitor2 : public OSMonitor, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN

    friend class LinuxMonitor2State;

public:
    LinuxMonitor2(S2E* s2e): OSMonitor(s2e) {}

    void initialize();

private:
    ConfigFile *m_cfg;

    BaseInstructions *m_base;

    // XXX: circular dependency
    ProcessExecutionDetector *m_detector;

    uint64_t m_kernelStart;
    bool m_terminateOnSegfault;
    bool m_terminateOnDivebyzero;
    bool m_updatePidexpensive;

    bool verifyCustomInstruction(S2EExecutionState *state,
                                uint64_t guestDataPtr,
                                uint64_t guestDataSize,
                                S2E_LINUXMON_COMMAND& cmd,
                                std::ostringstream& os);
    void handleElfBinaryLoad(S2EExecutionState *s, const S2E_LINUXMON_COMMAND_ELFBINARY_LOAD &p);

    void handleTaskExit(S2EExecutionState *s, const S2E_LINUXMON_COMMAND &p);

    void handleTaskSwitch(S2EExecutionState *s, const S2E_LINUXMON_COMMAND &p);

public:


    sigc::signal<void,
        S2EExecutionState *,
        const S2E_LINUXMON_COMMAND &,
        bool /* done */
    >onCustomInstuction;

    /* Quick hack to report segment faults */
    sigc::signal<void,
        S2EExecutionState*,
        uint64_t /* pid */,
        uint64_t /* pc */
    >onSegmentFault;

    /* Quick hack to report divide by zero faults */
     sigc::signal<void,
         S2EExecutionState*,
         uint64_t /* pid */,
         uint64_t /* pc */,
         bool /* isFloat */
     >onDividebyZero;



    virtual bool getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I);
    virtual bool getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E);
    virtual bool getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R);
    virtual bool isKernelAddress(uint64_t pc) const;
    virtual uint64_t getAddressSpace(S2EExecutionState *s, uint64_t pc);
    virtual bool getCurrentStack(S2EExecutionState *s, uint64_t *base, uint64_t *size);


    bool getFaultAddress(S2EExecutionState *state, uint64_t siginfo_ptr, uint64_t *address);

    //reg is a QEMU register identifier (e.g., R_EAX...)
    bool getRegisterAtFault(S2EExecutionState *state, uint64_t task_ptr, const char *reg_name, uint64_t *value);

    uint64_t getPid(S2EExecutionState *state, uint64_t pc);
    uint64_t getPid(S2EExecutionState *state) {
        return getPid(state, state->getPc());
    }
    uint64_t getTid(S2EExecutionState *state) {
        return getPid(state);
    }


    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                   uint64_t guestDataPtr,
                                   uint64_t guestDataSize);

    bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name);
};


} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LINUX_MONITOR_2_H
