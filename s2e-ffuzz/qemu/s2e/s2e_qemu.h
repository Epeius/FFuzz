///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_QEMU_H
#define S2E_QEMU_H

#include <inttypes.h>

#ifdef __cplusplus
namespace s2e {
    struct S2ETranslationBlock;
}
using s2e::S2ETranslationBlock;
#else
struct S2E;
struct S2EExecutionState;
struct S2ETranslationBlock;
#endif

struct TranslationBlock;
struct TCGLLVMContext;
struct S2ETLBEntry;
struct QDict;
struct MemoryRegion;

// XXX
struct CPUX86State;

#ifdef __cplusplus
extern "C" {
#endif


struct PCIBus;

/**************************/
/* Functions from S2E.cpp */

/** Initialize S2E instance. Called by main() */
void s2e_initialize(int argc, char** argv,
                           struct TCGLLVMContext *tcgLLVMContext,
                           const char *s2e_config_file,
                           const char *s2e_output_dir,
                           int setup_unbuffered_stream,
                           int verbose, unsigned max_processes);

/** Relese S2E instance and all S2E-related objects. Called by main() */
void s2e_close(void);
void s2e_close_arg(void);
void *get_s2e(void);

void s2e_flush_output_streams(void);
void s2e_debug_print(const char *fmtstr, ...);
void s2e_warning_print(const char *fmtstr, ...);
void s2e_debug_print_hex(void *addr, int len);
void print_stacktrace(void (*print_func)(const char *fmt, ...), const char *reason);

void s2e_print_apic(struct CPUX86State *env);


#include "s2e_qemu_coreplugin.h"


/**********************************/
/* Functions from S2EExecutor.cpp */

/** Variable that holds the latest return address when
    executiong helper code from KLEE */
//extern void* g_s2e_exec_ret_addr;

/** Global variable that determines whether to fork on
    symbolic memory addresses */
extern int g_s2e_fork_on_symbolic_address;

/** Global variable that determines whether to make
    symbolic I/O memory addresses concrete */
extern int g_s2e_concretize_io_addresses;

/** Global variable that determines whether to make
    symbolic I/O writes concrete */
extern int g_s2e_concretize_io_writes;


/** Prevent anything from flushing the TLB cache */
extern int g_se_disable_tlb_flush;

/** Fast check for cpu-exec.c */
extern int g_s2e_fast_concrete_invocation;

extern char *g_s2e_running_concrete;

extern char *g_s2e_running_exception_emulation_code;

extern uintptr_t g_se_dirty_mask_addend;

extern int g_s2e_single_path_mode;

#if defined CONFIG_LIBS2E
extern int g_exit_on_sti;
#endif

/** Create initial S2E execution state */
void s2e_create_initial_state(void);

/** Initialize symbolic execution machinery. Should be called after
    QEMU pc is completely constructed */
void s2e_initialize_execution(int execute_always_klee);

void s2e_register_cpu(struct CPUX86State* cpu_env);

void s2e_register_ram(struct MemoryRegion *region,
                      uint64_t start_address, uint64_t size,
                      uint64_t host_address, int is_shared_concrete,
                      int save_on_context_switch, const char *name);

uintptr_t se_get_host_address(uint64_t paddr);

void s2e_read_ram_concrete(uint64_t host_address, void* buf, uint64_t size);

void s2e_write_ram_concrete(uint64_t host_address, const uint8_t* buf, uint64_t size);

/** This function is called when RAM is read by concretely executed
    generated code. If the memory location turns out to be symbolic,
    this function will either concretize it of switch to execution
    in KLEE */
void s2e_read_ram_concrete_check(uint64_t host_address, uint8_t* buf, uint64_t size);


void s2e_read_register_concrete(unsigned offset, uint8_t* buf, unsigned size);

void s2e_write_register_concrete(unsigned offset, uint8_t* buf, unsigned size);

/* helpers that should be run as LLVM functions */
void s2e_set_cc_op_eflags(struct CPUX86State *state);


/** Allocate S2E parts of the tanslation block. Called from tb_alloc() */
void se_tb_alloc(struct TranslationBlock *tb);

/** Free S2E parts of the translation block. Called from tb_flush() and tb_free() */
void se_tb_free(struct TranslationBlock *tb);

/** Called after LLVM code generation
    in order to update tb->se_tb->llvm_function */
void s2e_set_tb_function(struct TranslationBlock *tb);

int s2e_is_tb_instrumented(struct TranslationBlock *tb);

void se_tb_gen_llvm(struct CPUX86State* env, struct TranslationBlock *tb);

void s2e_flush_tb_cache();
void s2e_increment_tb_stats(struct TranslationBlock *tb);
void s2e_flush_tlb_cache(void);
void se_flush_tlb_cache_page(void *objectState, int mmu_idx, int index);

#ifndef CONFIG_LIBS2E
typedef uintptr_t (*se_qemu_tb_exec_t)(struct CPUX86State* env1, struct TranslationBlock* tb);
typedef void (*se_do_interrupt_all_t)(int intno, int is_int, int error_code,
                                            uintptr_t next_eip, int is_hw);
#endif

extern se_qemu_tb_exec_t se_qemu_tb_exec;

/* Called by QEMU when execution is aborted using longjmp */
void s2e_qemu_cleanup_tb_exec();

int s2e_qemu_finalize_tb_exec(void);

void s2e_init_timers(void);


void s2e_init_device_state(void);

#if 0
void s2e_qemu_put_byte(struct S2EExecutionState *s, int v);
int s2e_qemu_get_byte(struct S2EExecutionState *s);
int s2e_qemu_peek_byte(struct S2EExecutionState *s);
int s2e_qemu_get_buffer(struct S2EExecutionState *s, uint8_t *buf, int size1);
int s2e_qemu_peek_buffer(struct S2EExecutionState *s, uint8_t *buf, int size1);
void s2e_qemu_put_buffer(struct S2EExecutionState *s, const uint8_t *buf, int size);
#endif

int s2e_is_zombie(void);
int s2e_is_speculative(void);
int s2e_is_yielded(void);
int s2e_is_runnable(void);
int s2e_is_running_concrete(void);

void s2e_reset_state_switch_timer(void);

void s2e_execute_cmd(const char *cmd);

void s2e_on_device_registration();
void s2e_on_device_activation(int bus_type, void *bus);
void s2e_on_pci_device_update_mappings(void *pci_device, int bar_index, uint64_t old_addr);

//Used by port IO for now
void s2e_switch_to_symbolic(void *retaddr) __attribute__ ((noreturn));

void se_ensure_symbolic(void);

int s2e_is_port_symbolic(uint64_t port);
int se_is_mmio_symbolic(struct MemoryRegion *mr, uint64_t address, uint64_t size);
int se_is_mmio_symbolic_b(struct MemoryRegion *mr, uint64_t address);
int se_is_mmio_symbolic_w(struct MemoryRegion *mr, uint64_t address);
int se_is_mmio_symbolic_l(struct MemoryRegion *mr, uint64_t address);
int se_is_mmio_symbolic_q(struct MemoryRegion *mr, uint64_t address);

void s2e_update_tlb_entry(struct CPUX86State* env,
                          int mmu_idx, uint64_t virtAddr, uint64_t hostAddr);

//Check that no asyc request are pending
int qemu_bh_empty(void);
void qemu_bh_clear(void);

void s2e_register_dirty_mask(uint64_t host_address, uint64_t size);
uint8_t se_read_dirty_mask(uint64_t host_address);
void se_write_dirty_mask(uint64_t host_address, uint8_t val);

void s2e_dma_read(uint64_t hostAddress, uint8_t *buf, unsigned size);
void s2e_dma_write(uint64_t hostAddress, uint8_t *buf, unsigned size);

void s2e_on_privilege_change(unsigned previous, unsigned current);
void s2e_on_page_directory_change(uint64_t previous, uint64_t current);

void s2e_on_initialization_complete(void);

void s2e_on_monitor_event(struct QDict *ret);

//Used by S2E.h to reinitialize timers in the forked process
int init_timer_alarm(int register_exit_handler);

int s2e_is_load_balancing();
int s2e_is_forking();

void se_setup_precise_pc(struct TranslationBlock* tb);
void s2e_fix_code_gen_ptr(struct TranslationBlock* tb, int code_gen_size);

void se_phys_section_print(void);
void se_phys_section_check(struct CPUX86State *cpu_state);

void se_tb_safe_flush(void);

/******************************************************/
/* Prototypes for special functions used in LLVM code */
/* NOTE: this functions should never be defined. They */
/* are implemented as a special function handlers.    */

#if defined(SYMBEX_LLVM_LIB)
target_ulong tcg_llvm_fork_and_concretize(target_ulong value,
                                      target_ulong knownMin,
                                      target_ulong knownMax,
                                      target_ulong reason);

void tcg_llvm_before_memory_access(target_ulong vaddr, uint64_t value, unsigned size, unsigned flags);

void tcg_llvm_after_memory_access(target_ulong vaddr, uint64_t value, unsigned size,
                                  unsigned flags, uintptr_t retaddr);

uint64_t tcg_llvm_trace_port_access(uint64_t port, uint64_t value,
                                unsigned bits, int isWrite);

void tcg_llvm_write_mem_io_vaddr(uint64_t value, int reset);
void tcg_llvm_make_symbolic(void *addr, unsigned nbytes, const char *name);
void tcg_llvm_get_value(void *addr, unsigned nbytes, bool addConstraint);
#endif


uint64_t s2e_read_mem_io_vaddr(int masked);

void s2e_kill_state(const char *message);

/* Register target-specific helpers with LLVM */
void helper_register_symbols(void);
void helper_register_symbol(const char *name, void *address);

#ifdef __cplusplus
}
#endif

#endif // S2E_QEMU_H
