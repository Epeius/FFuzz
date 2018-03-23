/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2014, CodeTickler, Inc
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
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef S2E_CGC_MONITOR

#define S2E_CGC_MONITOR

#include "s2e.h"

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
    };
    char currentName[32]; // not NULL terminated
} __attribute__((packed));

#endif
