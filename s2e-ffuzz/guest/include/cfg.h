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


#ifndef _S2E_CFG_H_

#define _S2E_CFG_H_

#include <s2e.h>
#include <inttypes.h>

typedef enum _S2E_CFG_COMMANDS {
    CFG_REGISTER_FUNCTION
} S2E_CFG_COMMANDS __attribute__((aligned(8)));

typedef struct _S2E_CFG_FUNCTION {
    uint64_t RunTimeFunctionAddress;
    uint64_t FunctionName;
} S2E_CFG_FUNCTION __attribute__((aligned(8)));

typedef struct _S2E_CFG_COMMAND {
    S2E_CFG_COMMANDS Command;
    union {
        S2E_CFG_FUNCTION Function;
    };
} S2E_CFG_COMMAND  __attribute__((aligned(8)));



static void s2e_cfg_register_function(void *function, const char *name)
{
    S2E_CFG_COMMAND Command;
    Command.Command = CFG_REGISTER_FUNCTION;
    Command.Function.FunctionName = (uintptr_t) name;
    Command.Function.RunTimeFunctionAddress = (uintptr_t) function;

    s2e_invoke_plugin("ControlFlowGraph", &Command, sizeof(Command));
}

#define S2E_CFG_REG_FUNC(func) s2e_cfg_register_function(&func, #func)


#endif
