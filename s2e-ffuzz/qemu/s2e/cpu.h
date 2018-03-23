///
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

///
/// This header gathers all qemu includes.
/// It must be used instead of manually including qemu headers
/// in every source file.
///

#ifndef __S2E_CPU_H__

#define __S2E_CPU_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_LIBS2E

#include <cpu/i386/cpu.h>
#include <cpu/i386/helper.h>
#include <cpu/exec.h>
#include <cpu/cpu-common.h>
#include <qemu-compiler.h>
#include <cpu/se_qemu.h>
#include <cpu/tlb.h>
#include <cpu/apic.h>
#include <cpu/ioport.h>
#include <cpu/cpus.h>

#include <qemu-timer.h>
#include <tcg/tcg-llvm.h>
#include <tcg/tcg.h>

#else // CONFIG_LIBS2E

#include "config.h"
#include <qemu-common.h>
#include <cpus.h>

#ifndef __QEMU_HELPER_H__
#define __QEMU_HELPER_H__
#include <helper.h>
#endif

#include <cpu-all.h>
#include <exec-all.h>
#include <cpu.h>
#include <memory.h>
#include <ioport.h>

#include <sysemu.h>
#include <tcg-llvm.h>
#include <tcg.h>
#include "disas.h"

#include <qemu-timer.h>

#endif // CONFIG_LIBS2E

//XXX: clean this up
#define QEMU_NORETURN __attribute__ ((__noreturn__))

extern struct CPUX86State *env;
void QEMU_NORETURN raise_exception(int exception_index);
void QEMU_NORETURN raise_exception_err(int exception_index, int error_code);
extern const uint8_t parity_table[256];
extern const uint8_t rclw_table[32];
extern const uint8_t rclb_table[32];

void se_do_interrupt_all(int intno, int is_int, int error_code,
                             target_ulong next_eip, int is_hw);
uint64_t helper_set_cc_op_eflags(void);

void s2e_gen_pc_update(void *context, target_ulong pc, target_ulong cs_base);
void s2e_gen_flags_update(void *context);

#ifdef __cplusplus
}
#endif

#endif
