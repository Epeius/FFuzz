///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_QEMU_COREPLUGIN_H

#define S2E_QEMU_COREPLUGIN_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef CONFIG_LIBS2E
enum special_instruction_t {
    RDTSC, SYSENTER, SYSCALL, PUSHIM
};
#else
#include <cpu/se_qemu.h>
#endif


/*********************************/
/* Functions from CorePlugin.cpp */

struct TranslationBlock;

void s2e_tcg_execution_handler(void* signal, uint64_t pc);
void s2e_tcg_custom_instruction_handler(uint64_t arg);

/** Called by the translator when a custom instruction is detected */
void s2e_tcg_emit_custom_instruction(uint64_t arg);

/** Called by the translator when an int xxx instruction is detected */
void s2e_on_translate_soft_interrupt_start(
        void *context,
        struct TranslationBlock *tb, uint64_t pc, unsigned vector);

/** Called by cpu_gen_code() at the beginning of translation process */
void s2e_on_translate_block_start(
        void *context,
        struct TranslationBlock *tb, uint64_t pc);

/** Called by cpu_gen_code() before the execution would leave the tb.
    staticTarget is 1 when the target pc at the end of the tb is known */
void s2e_on_translate_block_end(
        struct TranslationBlock *tb, uint64_t insPc,
        int staticTarget, uint64_t targetPc);


/** Called when gen_intermediate_code_internal() returns */
void s2e_on_translate_block_complete(struct TranslationBlock *tb, uint64_t pc);

/** Called by cpu_gen_code() before translation of each instruction */
void s2e_on_translate_instruction_start(
        void *context,
        struct TranslationBlock* tb, uint64_t pc);

/** Called by cpu_gen_code() after translation of certain special types of instructions */
void s2e_on_translate_special_instruction_end(
        void *context,
        struct TranslationBlock *tb, uint64_t pc, enum special_instruction_t type,
        int update_pc);

/** Called by cpu_gen_code() after translation of each instruction */
void s2e_on_translate_instruction_end(
        void *context,
        struct TranslationBlock* tb, uint64_t pc, uint64_t nextpc);

/** Called by cpu_gen_code() before translation of each jump instruction */
void s2e_on_translate_jump_start(
        void *context,
        struct TranslationBlock* tb, uint64_t pc,
        int jump_type);

void s2e_on_translate_indirect_cti_start(void *context, struct TranslationBlock *tb, uint64_t pc, int rm, int op,
                                         int offset);

void s2e_on_translate_lea_rip_relative(
        void *context, struct TranslationBlock *tb, uint64_t pc, uint64_t addr);

void s2e_on_translate_register_access(
        struct TranslationBlock *tb, uint64_t pc,
        uint64_t readMask, uint64_t writeMask, int isMemoryAccess);

void s2e_on_exception(unsigned intNb);

int s2e_on_call_return_translate(uint64_t pc, int isCall);

/** Called on memory accesses from generated code */
#define MEM_TRACE_FLAG_IO 1
#define MEM_TRACE_FLAG_WRITE 2
#define MEM_TRACE_FLAG_PRECISE 4
#define MEM_TRACE_FLAG_PLUGIN 8

void s2e_after_memory_access(
        uint64_t vaddr, uint64_t value, unsigned size,
        unsigned flags, uintptr_t retaddr);

extern unsigned *g_s2e_before_memory_access_signals_count;
extern unsigned *g_s2e_after_memory_access_signals_count;
extern unsigned *g_s2e_on_translate_soft_interrupt_signals_count;
extern unsigned *g_s2e_on_translate_block_start_signals_count;
extern unsigned *g_s2e_on_translate_block_end_signals_count;
extern unsigned *g_s2e_on_translate_block_complete_signals_count;
extern unsigned *g_s2e_on_translate_instruction_start_signals_count;
extern unsigned *g_s2e_on_translate_special_instruction_end_signals_count;
extern unsigned *g_s2e_on_translate_jump_start_signals_count;
extern unsigned *g_s2e_on_translate_lea_rip_relative_signals_count;
extern unsigned *g_s2e_on_translate_instruction_end_signals_count;
extern unsigned *g_s2e_on_translate_register_access_signals_count;
extern unsigned *g_s2e_on_exception_signals_count;
extern unsigned *g_s2e_on_page_fault_signals_count;
extern unsigned *g_s2e_on_tlb_miss_signals_count;
extern unsigned *g_s2e_on_port_access_signals_count;
extern unsigned *g_s2e_on_privilege_change_signals_count;
extern unsigned *g_s2e_on_page_directory_change_signals_count;
extern unsigned *g_s2e_on_call_return_signals_count;

extern unsigned g_s2e_enable_mmio_checks;

extern int g_s2e_allow_custom_instructions;

/** Called on port access from helper code */
void s2e_trace_port_access(
        uint64_t port, uint64_t value, unsigned bits,
        int isWrite, void *retaddr);


void s2e_on_page_fault(uint64_t addr, int is_write, void *retaddr);
void s2e_on_tlb_miss(uint64_t addr, int is_write, void *retaddr);



#ifdef __cplusplus
}
#endif

#endif
