/*
 *  Host code generation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The file was modified for S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 *
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "config.h"

#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "disas.h"
#include "tcg.h"
#include "qemu-timer.h"

#ifdef CONFIG_SYMBEX
#include "tcg-llvm.h"
#include "s2e/s2e_qemu.h"
#endif

/* code generation context */
TCGContext tcg_ctx;

#if defined(CONFIG_SYMBEX) && defined(TCG_KEEP_OPC)

/* S2E preserves the micro-op cache to properly handle retranslation to LLVM */

unsigned g_gen_opc_buf_count;
unsigned g_gen_opparam_buf_count;

uint16_t *g_gen_opc_buf;
TCGArg *g_gen_opparam_buf;

uint16_t *g_gen_opc_buf_max;
TCGArg *g_gen_opparam_buf_max;

/* Preserve variable assignments to generate LLVM code when needed */
unsigned g_gen_temps_count;
TCGTemp *g_gen_temps_buf;
TCGTemp *g_gen_temps_buf_max;
TCGTemp *gen_temps_buf;

uint16_t *gen_opc_buf;
TCGArg *gen_opparam_buf;


#else
uint16_t gen_opc_buf[OPC_BUF_SIZE];
TCGArg gen_opparam_buf[OPPARAM_BUF_SIZE];
#endif


target_ulong gen_opc_pc[OPC_BUF_SIZE];
uint16_t gen_opc_icount[OPC_BUF_SIZE];
uint8_t gen_opc_instr_start[OPC_BUF_SIZE];
uint8_t gen_opc_instr_size[OPC_BUF_SIZE];

#ifdef CONFIG_SYMBEX
int cpu_gen_flush_needed(void)
{
#ifdef TCG_KEEP_OPC
    return ((g_gen_opc_buf_max - gen_opc_buf < OPC_BUF_SIZE) ||
            (g_gen_opparam_buf_max - gen_opparam_buf < OPPARAM_BUF_SIZE) ||
            (g_gen_temps_buf_max - gen_temps_buf) < TCG_MAX_TEMPS);
#else
    return 0;
#endif
}

void cpu_gen_flush(void)
{
#ifdef TCG_KEEP_OPC
    gen_opc_buf = g_gen_opc_buf;
    gen_opparam_buf = g_gen_opparam_buf;
    gen_temps_buf = g_gen_temps_buf;
#endif
}

void cpu_gen_init_opc(void)
{
#ifdef TCG_KEEP_OPC
    //XXX: these constants have to be fine-tuned.
    extern int code_gen_max_blocks;
    g_gen_opc_buf_count = 32*code_gen_max_blocks;
    g_gen_opc_buf = g_malloc0(g_gen_opc_buf_count * sizeof(uint16_t));
    g_gen_opc_buf_max = g_gen_opc_buf + g_gen_opc_buf_count;

    g_gen_opparam_buf_count = 4*32*code_gen_max_blocks;
    g_gen_opparam_buf = g_malloc0(g_gen_opc_buf_count * sizeof(TCGArg));
    g_gen_opparam_buf_max = g_gen_opparam_buf + g_gen_opparam_buf_count;

    g_gen_temps_count = 8*code_gen_max_blocks;
    g_gen_temps_buf = g_malloc0(g_gen_temps_count * sizeof(TCGTemp));
    g_gen_temps_buf_max = g_gen_temps_buf + g_gen_temps_count;

    gen_opc_buf = g_gen_opc_buf;
    gen_opparam_buf = g_gen_opparam_buf;
    gen_temps_buf = g_gen_temps_buf;
#endif
}

#endif

void cpu_gen_init(void)
{
    tcg_context_init(&tcg_ctx);
}

/* return non zero if the very first instruction is invalid so that
   the virtual CPU can trigger an exception.

   '*gen_code_size_ptr' contains the size of the generated code (host
   code).
*/

int cpu_gen_code(CPUArchState *env, TranslationBlock *tb, int *gen_code_size_ptr)
{
    TCGContext *s = &tcg_ctx;
    uint8_t *gen_code_buf;
    int gen_code_size;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count1++; /* includes aborted translations because of
                       exceptions */
    ti = profile_getclock();
#endif
    tcg_func_start(s);

#if defined(CONFIG_SYMBEX) && defined(TCG_KEEP_OPC)
    tb->gen_opc_buf = gen_opc_buf;
    tb->gen_opparam_buf = gen_opparam_buf;
#endif

    gen_intermediate_code(env, tb);

    /* generate machine code */
    gen_code_buf = tb->tc_ptr;
    tb->tb_next_offset[0] = 0xffff;
    tb->tb_next_offset[1] = 0xffff;
    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif

#ifdef CONFIG_PROFILER
    s->tb_count++;
    s->interm_time += profile_getclock() - ti;
    s->code_time -= profile_getclock();
#endif

#ifdef CONFIG_SYMBEX
    s->tb = tb;
#endif

    gen_code_size = tcg_gen_code(s, gen_code_buf);
    *gen_code_size_ptr = gen_code_size;

#ifdef CONFIG_SYMBEX
    tb->tc_size = gen_code_size;
    tcg_calc_regmask(s, &tb->reg_rmask, &tb->reg_wmask,
                     &tb->helper_accesses_mem);

    tb->instrumented = s2e_is_tb_instrumented(tb);
    s2e_increment_tb_stats(tb);

#ifdef TCG_KEEP_OPC
    gen_opc_buf = gen_opc_ptr;
    gen_opparam_buf = gen_opparam_ptr;
    tb->gen_opc_count = (unsigned)(gen_opc_buf - tb->gen_opc_buf);

    /* Save variables */
    tb->tcg_temps = gen_temps_buf;
    tb->tcg_nb_globals = tcg_ctx.nb_globals;
    tb->tcg_nb_temps = tcg_ctx.nb_temps;
    unsigned vars = tb->tcg_nb_globals + tb->tcg_nb_temps;
    memcpy(tb->tcg_temps, tcg_ctx.temps, vars * sizeof(TCGTemp));
    gen_temps_buf += vars;
#endif
#endif


#ifdef CONFIG_PROFILER
    s->code_time += profile_getclock();
    s->code_in_len += tb->size;
    s->code_out_len += gen_code_size;
#endif

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM)) {
        qemu_log("OUT: [size=%d]\n", *gen_code_size_ptr);
        log_disas(tb->tc_ptr, *gen_code_size_ptr);
        qemu_log("\n");
        qemu_log_flush();
    }
#endif
    return 0;
}

#ifdef CONFIG_SYMBEX

#ifdef S2E_ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE
void restore_state_to_opc_compare(CPUX86State *env, TranslationBlock *tb, int pc_pos);
/* The cpu state corresponding to 'searched_pc' is restored.
 */
static int cpu_restore_state_original(TranslationBlock *tb,
                      CPUArchState *env, uintptr_t searched_pc)
{
    TCGContext *s = &tcg_ctx;
    int j;
    uintptr_t tc_ptr;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    //XXX: this must be deterministic (might not be because of S2E events)! Store the TB somewhere???
    gen_intermediate_code_pc(env, tb);

    if (use_icount) {
        /* Reset the cycle counter to the start of the block.  */
        env->icount_decr.u16.low += tb->icount;
        /* Clear the IO flag.  */
        env->can_do_io = 0;
    }

    /* find opc index corresponding to search_pc */
    tc_ptr = (uintptr_t)tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif
    j = tcg_gen_code_search_pc(s, (uint8_t *)tc_ptr, searched_pc - tc_ptr);
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (gen_opc_instr_start[j] == 0)
        j--;

    env->icount_decr.u16.low -= gen_opc_icount[j];

    restore_state_to_opc_compare(env, tb, j);

    return 0;
}
#endif

int cpu_restore_state_retranslate(TranslationBlock *tb,
                      CPUArchState *env, uintptr_t searched_pc);

int cpu_restore_state(TranslationBlock *tb,
                      CPUArchState *env, uintptr_t searched_pc)
{
#if 0
    qemu_log("RESTORE: searched_pc=%#"PRIx64" tc_ptr=%#"PRIx64" tc_ptr_max=%#"PRIx64" icount=%d cur_pc=%#x\n",
             searched_pc, (uintptr_t)tb->tc_ptr, (uintptr_t)tb->tc_ptr + tb->tc_size, tb->icount, env->eip);
#endif
    if (!s2e_is_running_concrete()) {
#ifdef S2E_ENABLE_PRECISE_EXCEPTION_DEBUGGING
        assert(env->eip == env->s2e_eip);
#endif
#ifdef S2E_ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE
            cpu_restore_state_original(tb, env, searched_pc);
#endif
        //XXX: Need to set the instruction size here
        env->restored_instruction_size = 0;
        assert(tb->llvm_function);
        return 0;
    }


#ifdef SE_ENABLE_RETRANSLATION
    if (!tb->instrumented) {
        assert(tb->precise_entries == -1);
        //Restore PC using retranslation
        return cpu_restore_state_retranslate(tb, env, searched_pc);
    }
#endif

    tb_precise_pc_t *p = tb->precise_pcs + tb->precise_entries - 1;
    assert(tb->precise_entries > 0);
    target_ulong next_pc = tb->pc + p->guest_pc_increment;
    while (p >= tb->precise_pcs) {
#if 0
        qemu_log("   current_host_pc=%#"PRIx64" current_guest_pc=%#x cc_op=%d tc_idx=%d\n",
                 p->host_pc, p->guest_pc, p->cc_op, p->opc);
#endif
        //assert(p->host_pc);

        if (((uintptr_t) tb->tc_ptr + p->host_pc_increment) <= searched_pc) {
            /* Found the guest program counter at the time of exception */
            se_restore_state_to_opc(env, tb, tb->pc + p->guest_pc_increment, p->cc_op, next_pc);
            env->restored_instruction_size = p->guest_inst_size;

#ifdef S2E_ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE
            cpu_restore_state_original(tb, env, searched_pc);
#endif
            return 0;
        }
        next_pc = tb->pc + p->guest_pc_increment;
        --p;
    }

    assert(false && "Could not find pc");
}

#endif

#ifdef CONFIG_SYMBEX
int cpu_restore_state_retranslate(TranslationBlock *tb,
                      CPUArchState *env, uintptr_t searched_pc)
#else

/* The cpu state corresponding to 'searched_pc' is restored.
 */
int cpu_restore_state(TranslationBlock *tb,
                      CPUArchState *env, uintptr_t searched_pc)
#endif
{
    TCGContext *s = &tcg_ctx;
    int j;
    uintptr_t tc_ptr;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

#ifdef CONFIG_PROFILER
    ti = profile_getclock();
#endif
    tcg_func_start(s);

    //XXX: this must be deterministic (might not be because of S2E events)! Store the TB somewhere???
    gen_intermediate_code_pc(env, tb);

    if (use_icount) {
        /* Reset the cycle counter to the start of the block.  */
        env->icount_decr.u16.low += tb->icount;
        /* Clear the IO flag.  */
        env->can_do_io = 0;
    }

    /* find opc index corresponding to search_pc */
    tc_ptr = (uintptr_t)tb->tc_ptr;
    if (searched_pc < tc_ptr)
        return -1;

    s->tb_next_offset = tb->tb_next_offset;
#ifdef USE_DIRECT_JUMP
    s->tb_jmp_offset = tb->tb_jmp_offset;
    s->tb_next = NULL;
#else
    s->tb_jmp_offset = NULL;
    s->tb_next = tb->tb_next;
#endif
    j = tcg_gen_code_search_pc(s, (uint8_t *)tc_ptr, searched_pc - tc_ptr);
    if (j < 0)
        return -1;
    /* now find start of instruction before */
    while (gen_opc_instr_start[j] == 0)
        j--;

    env->icount_decr.u16.low -= gen_opc_icount[j];

    restore_state_to_opc(env, tb, j);

#ifdef CONFIG_PROFILER
    s->restore_time += profile_getclock() - ti;
    s->restore_count++;
#endif

    return 0;
}


#ifdef CONFIG_SYMBEX

/**
 * Generates LLVM code for already translated TB.
 * We need to retranslate to micro-ops and to machine code because:
 *   - QEMU throws away micro-ops and storing them is too expensive (TCG_KEEP_OPC)
 *   - x86 and LLVM code must be semantically equivalent (same instrumentation in both, etc.)
 */
int cpu_gen_llvm(CPUArchState *env, TranslationBlock *tb)
{
    TCGContext *s = &tcg_ctx;
    assert(tb->llvm_function == NULL);

    /* Need to retranslate the code here because QEMU throws
       away intermediate representation once machine code is generated. */

#ifdef TCG_KEEP_OPC
    /* Restore variables */
    unsigned vars = tb->tcg_nb_globals + tb->tcg_nb_temps;
    memcpy(tcg_ctx.temps, tb->tcg_temps, vars * sizeof(TCGTemp));

    uint16_t *gen_opc_buf_prev = gen_opc_buf;
    TCGArg *gen_opparam_buf_pref = gen_opparam_buf;

    gen_opc_buf = tb->gen_opc_buf;
    gen_opparam_buf = tb->gen_opparam_buf;
#endif

    tcg_llvm_gen_code(tcg_llvm_ctx, s, tb);
    s2e_set_tb_function(tb);

#ifdef TCG_KEEP_OPC
    gen_opc_buf = gen_opc_buf_prev;
    gen_opparam_buf = gen_opparam_buf_pref;
#endif
    return 0;
}

#endif
