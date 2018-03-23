///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_CGC_MONITOR_H
#define S2E_PLUGINS_CGC_MONITOR_H

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

#define S2E_CGCMON_COMMAND_VERSION 0x201606121741ULL // date +%Y%m%d%H%M

enum S2E_CGCMON_COMMANDS {
    SEGFAULT,
    PROCESS_LOAD,
    READ_DATA,
    WRITE_DATA,
    FD_WAIT,
    RANDOM,
    READ_DATA_POST,
    CONCOLIC_ON,
    CONCOLIC_OFF,
    GET_CFG_BOOL,
    HANDLE_SYMBOLIC_ALLOCATE_SIZE,
    HANDLE_SYMBOLIC_TRANSMIT_BUFFER,
    HANDLE_SYMBOLIC_RECEIVE_BUFFER,
    HANDLE_SYMBOLIC_RANDOM_BUFFER,
    COPY_TO_USER,
    UPDATE_MEMORY_MAP,
    SET_CB_PARAMS
};

struct S2E_CGCMON_COMMAND_PROCESS_LOAD {
    uint64_t process_id;

    uint64_t entry_point;

    uint64_t cgc_header;
    uint64_t start_code;
    uint64_t end_code;
    uint64_t start_data;
    uint64_t end_data;
    uint64_t start_stack;

    char process_path[128]; // not NULL terminated
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_READ_DATA {
    uint64_t fd;
    uint64_t buffer;
    uint64_t buffer_size;
    uint64_t size_expr_addr;
    uint64_t result_addr;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_READ_DATA_POST {
    uint64_t fd;
    uint64_t buffer;
    uint64_t buffer_size;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_WRITE_DATA {
    uint64_t fd;
    uint64_t buffer;
    uint64_t buffer_size_addr;
    uint64_t size_expr_addr;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_FD_WAIT {
    uint64_t tv_sec;
    uint64_t tv_nsec;
    uint64_t has_timeout;
    uint64_t nfds;
    uint64_t invoke_orig;
    int64_t result;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_SEG_FAULT {
    uint64_t pc;
    uint64_t address;
    uint64_t fault;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_RANDOM {
    uint64_t buffer;
    uint64_t buffer_size;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_GET_CFG_BOOL {
    uint64_t key_addr;
    uint64_t value;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_SIZE {
    uint64_t size_addr;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_BUFFER {
    uint64_t ptr_addr;
    uint64_t size_addr;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_COPY_TO_USER {
    uint64_t user_addr;
    uint64_t addr;
    uint64_t count;
    uint64_t done;
    uint64_t ret;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND_UPDATE_MEMORY_MAP {
    uint64_t count;
    uint64_t buffer;
} __attribute__((packed));

#define S2E_CGCMON_MAX_SEED_SIZE 64
#define S2E_CGCMON_CGC_SEED_SIZE 48

struct S2E_CGCMON_COMMAND_SET_CB_PARAMS {
    int64_t cgc_max_transmit;
    int64_t cgc_max_receive;
    int64_t skip_rng_count;

    /// \brief Guest pointer to the full seed.
    ///
    /// This pointer is null in case no seed has been
    /// passed to the CB as a command line argument.
    /// Plugin code should not write to this pointer,
    /// and instead use cgc_seed if it wants to modify
    /// the existing seed or create a new one.
    uint64_t cgc_seed_ptr;

    /// \brief In/out length of the seed
    ///
    /// The guest sets this value to the size of the existing
    /// seed. Plugin code may overwrite it with the size of
    /// the new seed, or set it to zero in case the existing
    /// seed should be used.
    int64_t cgc_seed_len;

    /// \brief Output buffer that stores a new rng seed.
    ///
    /// Plugin code may write a new seed to this buffer, up to
    /// 64 bytes in size.
    uint8_t cgc_seed[S2E_CGCMON_MAX_SEED_SIZE];

} __attribute__((packed));

#define S2E_CGCMON_VM_READ      (1u << 0)
#define S2E_CGCMON_VM_WRITE     (1u << 1)
#define S2E_CGCMON_VM_EXEC      (1u << 2)

struct S2E_CGCMON_VMA {
    uint64_t start;
    uint64_t end;
    uint64_t flags;
} __attribute__((packed));

struct S2E_CGCMON_COMMAND {
    uint64_t version;
    enum S2E_CGCMON_COMMANDS Command;
    uint64_t currentPid;
    union {
        struct S2E_CGCMON_COMMAND_PROCESS_LOAD ProcessLoad;
        struct S2E_CGCMON_COMMAND_READ_DATA Data;
        struct S2E_CGCMON_COMMAND_WRITE_DATA WriteData;
        struct S2E_CGCMON_COMMAND_FD_WAIT FDWait;
        struct S2E_CGCMON_COMMAND_SEG_FAULT SegFault;
        struct S2E_CGCMON_COMMAND_RANDOM Random;
        struct S2E_CGCMON_COMMAND_READ_DATA_POST DataPost;
        struct S2E_CGCMON_COMMAND_GET_CFG_BOOL GetCfgBool;
        struct S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_SIZE SymbolicSize;
        struct S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_BUFFER SymbolicBuffer;
        struct S2E_CGCMON_COMMAND_COPY_TO_USER CopyToUser;
        struct S2E_CGCMON_COMMAND_UPDATE_MEMORY_MAP UpdateMemoryMap;
        struct S2E_CGCMON_COMMAND_SET_CB_PARAMS CbParams;
    };
    char currentName[32]; // not NULL terminated
} __attribute__((packed));

template<typename T> T& operator<<(T &stream, const S2E_CGCMON_VMA &v) {
    stream << hexval(v.start) << ".." << hexval(v.end) << " "
           << (v.flags & S2E_CGCMON_VM_READ ? 'r' : '-')
           << (v.flags & S2E_CGCMON_VM_WRITE ? 'w' : '-')
           << (v.flags & S2E_CGCMON_VM_EXEC ? 'x' : '-');
    return stream;
}

template<typename T> T& operator<<(T &stream, const S2E_CGCMON_COMMANDS &c) {
    switch(c) {
        case SEGFAULT: stream << "SEGFAULT"; break;
        case PROCESS_LOAD: stream << "PROCESS_LOAD"; break;
        case READ_DATA: stream << "READ_DATA"; break;
        case WRITE_DATA: stream << "WRITE_DATA"; break;
        case FD_WAIT: stream << "FD_WAIT"; break;
        case RANDOM: stream << "RANDOM"; break;
        case READ_DATA_POST: stream << "READ_DATA_POST"; break;
        case CONCOLIC_ON: stream << "CONCOLIC_ON"; break;
        case CONCOLIC_OFF: stream << "CONCOLIC_OFF"; break;
        case GET_CFG_BOOL: stream << "GET_CFG_BOOL"; break;
        case HANDLE_SYMBOLIC_ALLOCATE_SIZE: stream << "HANDLE_SYMBOLIC_ALLOCATE_SIZE"; break;
        case HANDLE_SYMBOLIC_TRANSMIT_BUFFER: stream << "HANDLE_SYMBOLIC_TRANSMIT_BUFFER"; break;
        case HANDLE_SYMBOLIC_RECEIVE_BUFFER: stream << "HANDLE_SYMBOLIC_RECEIVE_BUFFER"; break;
        case HANDLE_SYMBOLIC_RANDOM_BUFFER: stream << "HANDLE_SYMBOLIC_RANDOM_BUFFER"; break;
        case COPY_TO_USER: stream << "COPY_TO_USER"; break;
        case UPDATE_MEMORY_MAP: stream << "UPDATE_MEMORY_MAP"; break;
        case SET_CB_PARAMS: stream << "SET_CB_PARAMS"; break;
        default: stream << "INVALID(" << (int) c << ")"; break;
    }
    return stream;
}

class CGCMonitorState;
class ProcessExecutionDetector;

namespace seeds {
class SeedSearcher;
}

class CGCMonitor : public OSMonitor, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN

    friend class CGCMonitorState;

public:
    CGCMonitor(S2E* s2e): OSMonitor(s2e) {}

    void initialize();

    double getTimeToFirstSegfault() {
        return m_timeToFirstSegfault;
    }

private:
    ConfigFile *m_cfg;

    Vmi *m_vmi;
    BaseInstructions *m_base;
    seeds::SeedSearcher *m_seedSearcher;

    // XXX: circular dependency
    ProcessExecutionDetector *m_detector;

    uint64_t m_kernelStart;
    llvm::DenseMap<uint64_t, llvm::StringRef> m_functionsMap;
    llvm::StringMap<uint64_t> m_functions;

    bool m_invokeOriginalSyscalls;

    bool m_printOpcodeOffsets;

    uint64_t m_symbolicReadLimitCount;
    uint64_t m_maxReadLimitCount;

    bool m_terminateOnSegfault;
    bool m_terminateProcessGroupOnSegfault;
    bool m_concolicMode;
    bool m_logWrittenData;
    bool m_handleSymbolicAllocateSize;
    bool m_handleSymbolicBufferSize;

    std::string m_feedConcreteData;

    time_t m_startTime;
    double m_timeToFirstSegfault;
    bool m_firstSegfault;

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                               TranslationBlock *tb,
                               uint64_t pc);

    void onLoadBinary(S2EExecutionState* state, uint64_t pc);
    void onLoadBinary_Return(S2EExecutionState* state, uint64_t pc);
    void onReceive(S2EExecutionState* state, uint64_t pc);
    void onSigSegv(S2EExecutionState* state, uint64_t pc);

    klee::ref<klee::Expr> readMemory8(S2EExecutionState *state, uint64_t pid, uint64_t addr);

public:
    enum SymbolicBufferType {
        SYMBUFF_RECEIVE,
        SYMBUFF_TRANSMIT,
        SYMBUFF_RANDOM
    };

    template<typename T> friend T& operator<<(T &stream, const SymbolicBufferType &type) {
        switch(type) {
            case SYMBUFF_RECEIVE: stream << "receive"; break;
            case SYMBUFF_TRANSMIT: stream << "transmit"; break;
            case SYMBUFF_RANDOM: stream << "random"; break;
            default: stream << "INVALID"; break;
        }
        return stream;
    }

    static bool bufferMustBeWritable(SymbolicBufferType t) {
        return t == SYMBUFF_RECEIVE || t == SYMBUFF_RANDOM;
    }

    sigc::signal<void,
        S2EExecutionState *,
        const S2E_CGCMON_COMMAND &,
        bool /* done */
    >onCustomInstuction;

    /* Quick hack to report segfaults */
    sigc::signal<void,
        S2EExecutionState*,
        uint64_t /* pid */,
        uint64_t /* pc */
    >onSegFault;

    sigc::signal<void,
        S2EExecutionState *,
        uint64_t /* pid */,
        uint64_t /* fd */,
        const std::vector<klee::ref<klee::Expr> > & /* data */,
        klee::ref<klee::Expr> /* sizeExpr */
    >onWrite;

    sigc::signal<void,
        S2EExecutionState *,
        uint64_t /* pid */,
        uint64_t /* fd */,
        uint64_t /* size */,
        const std::vector<std::pair<std::vector<klee::ref<klee::Expr> >, std::string> > & /* data */,
        klee::ref<klee::Expr> /* sizeExpr */
    >onSymbolicRead;

    sigc::signal<void,
        S2EExecutionState *,
        uint64_t /* pid */,
        uint64_t /* fd */,
        const std::vector<uint8_t> &
    >onConcreteRead;

    sigc::signal<void,
        S2EExecutionState *,
        uint64_t /* pid */,
        const std::vector<klee::ref<klee::Expr>> & /* data */
    >onRandom;

    /// \brief onSymbolicBuffer is emitted when a symbolic buffer is passed as
    /// argument to the system call
    ///
    /// This event will be emitted when buffer pointer is symbolic.
    sigc::signal<void,
        S2EExecutionState *,
        uint64_t /* pid */,
        SymbolicBufferType /* type */,
        klee::ref<klee::Expr> /* ptr */,
        klee::ref<klee::Expr> /* size */
    >onSymbolicBuffer;

    typedef std::vector<S2E_CGCMON_VMA> MemoryMap;

    /// \brief onUpdateMemoryMap is emitted when the memory layout
    /// of the guest process changes
    ///
    /// Currently event is emitted after process is loaded, and also
    /// after allocate and deallocate syscalls.
    sigc::signal<void,
        S2EExecutionState *,
        uint64_t /* pid */,
        const MemoryMap & /* map */
    >onUpdateMemoryMap;

    virtual bool getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I);
    virtual bool getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E);
    virtual bool getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R);
    virtual bool isKernelAddress(uint64_t pc) const;
    virtual uint64_t getAddressSpace(S2EExecutionState *s, uint64_t pc);
    virtual bool getCurrentStack(S2EExecutionState *s, uint64_t *base, uint64_t *size);

    void handleProcessLoad(S2EExecutionState *s, const S2E_CGCMON_COMMAND_PROCESS_LOAD &p);

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

    void getPreFeedData(S2EExecutionState *state, uint64_t pid, uint64_t count, std::vector<uint8_t> &data);
    void getRandomData(S2EExecutionState *state, uint64_t count, std::vector<uint8_t> &data);
    klee::ref<klee::Expr> makeSymbolicRead(S2EExecutionState *state, uint64_t pid, uint64_t fd, uint64_t buf, uint64_t count, klee::ref<klee::Expr> countExpr);

    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                   uint64_t guestDataPtr,
                                   uint64_t guestDataSize);

    bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name);

    static void FindMemoryPages(const MemoryMap &map, bool mustBeWritable, bool mustBeExecutable, std::unordered_set<uint64_t> &pages);
    const MemoryMap& getMemoryMap(S2EExecutionState *state, uint64_t pid);
    const MemoryMap& getMemoryMap(S2EExecutionState *state) {
        return getMemoryMap(state, getPid(state));
    }

    unsigned getSymbolicReadsCount(S2EExecutionState *state) const;

    static bool isReadFd(uint32_t fd);
    static bool isWriteFd(uint32_t fd);

private:
    uint64_t getMaxValue(S2EExecutionState *state, klee::ref<klee::Expr> value);
    void handleSymbolicSize(S2EExecutionState *state, uint64_t pid, uint64_t safeLimit, klee::ref<klee::Expr> size, uint64_t sizeAddr);
    void handleSymbolicBuffer(S2EExecutionState *state, uint64_t pid, SymbolicBufferType type, uint64_t ptrAddr, uint64_t sizeAddr);

    void printOpcodeOffsets(S2EExecutionState *state);
    void handleReadData(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_READ_DATA &d);
    void handleReadDataPost(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_READ_DATA_POST &d);
    void handleWriteData(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_WRITE_DATA &d);
    void handleFdWait(S2EExecutionState *state, S2E_CGCMON_COMMAND &d, uintptr_t addr);
    void handleRandom(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_RANDOM &d);
    void handleGetCfgBool(S2EExecutionState *state, uint64_t pid, S2E_CGCMON_COMMAND_GET_CFG_BOOL &d);
    void handleSymbolicAllocateSize(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_SIZE &d);
    void handleSymbolicReceiveBuffer(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d);
    void handleSymbolicTransmitBuffer(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d);
    void handleSymbolicRandomBuffer(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_HANDLE_SYMBOLIC_BUFFER &d);
    void handleCopyToUser(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_COPY_TO_USER &d);
    void handleUpdateMemoryMap(S2EExecutionState *state, uint64_t pid, const S2E_CGCMON_COMMAND_UPDATE_MEMORY_MAP &d);
    void handleSetParams(S2EExecutionState *state, uint64_t pid, S2E_CGCMON_COMMAND_SET_CB_PARAMS &d);
};


} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CGC_MONITOR_H
