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
 * All contributors are listed in the S2E-AUTHORS file.
 */


#ifndef _S2E_RAWMONITOR_H_

#define _S2E_RAWMONITOR_H_

#include <s2e.h>
#include <inttypes.h>

typedef struct S2E_RAWMONITOR_MODULE_LOAD {
    uint64_t path;
    uint64_t name;
    uint64_t nativeBase;
    uint64_t loadBase;
    uint64_t entryPoint;
    uint64_t size;
    uint64_t pid;
    uint64_t kernelMode;
} S2E_RAWMONITOR_MODULE_LOAD __attribute__((aligned(8)));

typedef struct S2E_RAWMONITOR_STACK {
    uint64_t GuestStackDescriptorPtr;
    uint64_t StackBase;
    uint64_t StackSize;
} S2E_RAWMONITOR_STACK __attribute__((aligned(8)));

typedef enum S2E_RAWMONITOR_COMMANDS {
    MODULE_LOAD, SET_CURRENT_STACK
} S2E_RAWMONITOR_COMMANDS __attribute__((aligned(8)));

typedef struct S2E_RAWMONITOR_COMMAND {
    S2E_RAWMONITOR_COMMANDS Command;
    union {
        S2E_RAWMONITOR_MODULE_LOAD ModuleLoad;
        S2E_RAWMONITOR_STACK Stack;
    };
} S2E_RAWMONITOR_COMMAND;


static inline void s2e_rawmonitor_register_stack(S2E_RAWMONITOR_STACK *stack)
{
    S2E_RAWMONITOR_COMMAND Command;
    Command.Command = SET_CURRENT_STACK;
    Command.Stack.GuestStackDescriptorPtr = (uintptr_t) stack;
    Command.Stack.StackBase = 0;
    Command.Stack.StackSize = 0;

    s2e_invoke_plugin("RawMonitor", &Command, sizeof(Command));
}

static inline void s2e_raw_monitor_load_module(const S2E_RAWMONITOR_MODULE_LOAD *module)
{
    S2E_RAWMONITOR_COMMAND Command;
    Command.Command = MODULE_LOAD;
    Command.ModuleLoad = *module;

    s2e_invoke_plugin("RawMonitor", &Command, sizeof(Command));
}


#endif
