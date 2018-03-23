/// Copyright (c) 2010, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2016, Cyberhaven, Inc
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are met:
///
///    * Redistributions of source code must retain the above copyright
///      notice, this list of conditions and the following disclaimer.
///
///    * Redistributions in binary form must reproduce the above copyright
///      notice, this list of conditions and the following disclaimer in the
///      documentation and/or other materials provided with the distribution.
///
///    * Neither the names of the copyright holders, nor the
///      names of its contributors may be used to endorse or promote products
///      derived from this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
/// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
/// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
/// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
/// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
/// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
/// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#ifndef __S2E_OPCODES__

#define __S2E_OPCODES__

#define OPCODE_SIZE (2 + 8)

//Central opcode repository for plugins that implement micro-operations
#define RAW_MONITOR_OPCODE   0xAA
#define MEMORY_TRACER_OPCODE 0xAC
#define STATE_MANAGER_OPCODE 0xAD
#define CODE_SELECTOR_OPCODE 0xAE
#define MODULE_EXECUTION_DETECTOR_OPCODE 0xAF
#define FUZZCONTROL_OPCODE 0xEA

#define VANILLA_QEMU_OPCODE 0xF0 //XXX: also defined in op_helper.c

//Expression evaluates to true if the custom instruction operand contains the
//specified opcode
#define OPCODE_CHECK(operand, opcode) ((((operand)>>8) & 0xFF) == (opcode))

//Get an 8-bit function code from the operand.
//This may or may not be used depending on how a plugin expects an operand to
//look like
#define OPCODE_GETSUBFUNCTION(operand) (((operand) >> 16) & 0xFF)


#define BASE_S2E_CHECK          0
#define BASE_S2E_ENABLE_SYMBEX  1
#define BASE_S2E_DISABLE_SYMBEX 2
#define BASE_S2E_MAKE_SYMBOLIC  3
#define BASE_S2E_IS_SYMBOLIC    4
#define BASE_S2E_GET_PATH_ID    5
#define BASE_S2E_KILL_STATE     6
#define BASE_S2E_PRINT_EXR      7
#define BASE_S2E_PRINT_MEM      8
#define BASE_S2E_ENABLE_FORK    9
#define BASE_S2E_DISABLE_FORK   0xa
#define BASE_S2E_INVOKE_PLUGIN  0xb
#define BASE_S2E_ASSUME         0xc
#define BASE_S2E_ASSUME_DISJ    0xd
#define BASE_S2E_ASSUME_RANGE   0xe
#define BASE_S2E_YIELD          0xf
#define BASE_S2E_PRINT_MSG      0x10
#define BASE_S2E_MAKE_CONCOLIC  0x11
#define BASE_S2E_BEGIN_ATOMIC   0x12
#define BASE_S2E_END_ATOMIC     0x13
#define BASE_S2E_CONCRETIZE     0x20
#define BASE_S2E_EXAMPLE        0x21
#define BASE_S2E_STATE_COUNT    0x30
#define BASE_S2E_INSTANCE_COUNT 0x31
#define BASE_S2E_SLEEP          0x32
#define BASE_S2E_WRITE_BUFFER   0x33
#define BASE_S2E_GET_RANGE      0x34
#define BASE_S2E_CONSTR_CNT     0x35
#define BASE_S2E_HEX_DUMP       0x36
#define BASE_S2E_SET_TIMER_INT  0x50
#define BASE_S2E_SET_APIC_INT   0x51
#define BASE_S2E_GET_OBJ_SZ     0x52
#define BASE_S2E_CLEAR_TEMPS    0x53
#define BASE_S2E_FORK_COUNT     0x54

#define VANILLA_QEMU_OPCODE     0xF0
#define VANILLA_QEMU_OPCODE_SAVEVM 1
#define VANILLA_QEMU_OPCODE_SAVEVM_QUERY 2


#endif
