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


#ifndef _S2E_SYMBHW_H_

#define _S2E_SYMBHW_H_

#include <s2e.h>
#include <inttypes.h>

/********************************************************/
/* SymbolicHardware */
typedef enum _S2E_SYMBHW_COMMANDS {
    SYMBHW_PLUG_IN,
    SYMBHW_HAS_PCI,
    SYMBHW_UNPLUG,
    SYMBHW_REGISTER_DMA_MEMORY,
    SYMBHW_UNREGISTER_DMA_MEMORY,
    SYMBHW_INJECT_INTERRUPT,
    SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS,
    SYMBHW_QUERY_RESOURCE_SIZE,
    SYMBHW_SELECT_NEXT_PCI_CONFIG,
} S2E_SYMBHW_COMMANDS __attribute__((aligned(8)));

typedef struct _S2E_SYMHW_DMA_MEMORY {
    uint64_t PhysicalAddress;
    uint64_t Size;
} S2E_SYMHW_DMA_MEMORY __attribute__((aligned(8)));

typedef struct _S2E_SYMHW_RESOURCE {
    /* Input to identify the resource */
    uint64_t PhysicalAddress;

    /* Output is a constrained symbolic size */
    uint64_t Size;
} S2E_SYMHW_RESOURCE __attribute__((aligned(8)));

typedef struct _S2E_SYMBHW_COMMAND {
    S2E_SYMBHW_COMMANDS Command;
    union {
        S2E_SYMHW_DMA_MEMORY Memory;
        S2E_SYMHW_RESOURCE Resource;
        uint64_t HasPci;
        uint64_t InterruptLevel;
        uint64_t SelectNextConfigSuccess;
    };
} S2E_SYMBHW_COMMAND __attribute__((aligned(8)));

static void S2ERegisterDmaRegion(uint64_t PhysicalAddress, uint64_t Size)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_REGISTER_DMA_MEMORY;
    Command.Memory.PhysicalAddress = PhysicalAddress;
    Command.Memory.Size = Size;

    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static void S2EFreeDmaRegion(uint64_t PhysicalAddress, uint64_t Size)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_UNREGISTER_DMA_MEMORY;
    Command.Memory.PhysicalAddress = PhysicalAddress;
    Command.Memory.Size = Size;

    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static int SymbHwPciDevPresent(void)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_HAS_PCI;
    Command.HasPci = 0;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
    return (int) Command.HasPci;
}

static void InjectSymbolicInterrupt(uint64_t Level)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_INJECT_INTERRUPT;
    Command.InterruptLevel = Level;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static void ActivateSymbolicPciBus()
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static int SymbHwQueryResourceSize(uint64_t PhysicalAddress, uint64_t *Size)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_QUERY_RESOURCE_SIZE;
    Command.Resource.PhysicalAddress = PhysicalAddress;
    Command.Resource.Size = 0;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
    *Size = Command.Resource.Size;
    return (*Size) != 0;
}

static void SymbhwHotPlug(int plugin)
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = plugin ? SYMBHW_PLUG_IN : SYMBHW_UNPLUG;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
}

static int SymbhwSelectNextConfig()
{
    S2E_SYMBHW_COMMAND Command;
    Command.Command = SYMBHW_SELECT_NEXT_PCI_CONFIG;
    Command.SelectNextConfigSuccess = 0;
    s2e_invoke_plugin("SymbolicHardware", &Command, sizeof(Command));
    return Command.SelectNextConfigSuccess;
}

#endif
