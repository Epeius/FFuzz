/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
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
 * Currently maintained by:
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef TCG_LLVM_H
#define TCG_LLVM_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

//#include "tcg.h"

/*****************************/
/* Functions for QEMU c code */

struct TranslationBlock;
struct TCGLLVMContext;

extern struct TCGLLVMContext* tcg_llvm_ctx;

struct TCGLLVMRuntime {
    // NOTE: The order of these are fixed !
    uint64_t helper_ret_addr;
    uint64_t helper_call_addr;
    uint64_t helper_regs[3];
    // END of fixed block

#ifdef CONFIG_SYMBEX
    /* run-time tb linking mechanism */
    uint8_t goto_tb;
#endif

#ifndef CONFIG_SYMBEX
    TranslationBlock *last_tb;
    uint64_t last_opc_index;
    uint64_t last_pc;
#endif
};

extern struct TCGLLVMRuntime tcg_llvm_runtime;

struct TCGLLVMContext* tcg_llvm_initialize(void);
void tcg_llvm_close(struct TCGLLVMContext *l);

void tcg_llvm_tb_alloc(struct TranslationBlock *tb);
void tcg_llvm_tb_free(struct TranslationBlock *tb);

void tcg_llvm_gen_code(struct TCGLLVMContext *l, struct TCGContext *s,
                       struct TranslationBlock *tb);
const char* tcg_llvm_get_func_name(struct TranslationBlock *tb);

#ifndef CONFIG_SYMBEX
int tcg_llvm_search_last_pc(struct TranslationBlock *tb, uintptr_t searched_pc);
#endif

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

/***********************************/
/* External interface for C++ code */

// Undefine cat from "compiler.h"
#undef cat

namespace llvm {
    class Function;
    class FunctionType;
    class LLVMContext;
    class Module;
    class ModuleProvider;
    class StoreInst;
    class ReturnInst;
    class BasicBlock;

namespace legacy {
    class FunctionPassManager;
}}

#ifdef STATIC_TRANSLATOR
#include <llvm/ADT/SmallVector.h>

struct TCGLLVMTBInfo {
    /* Return instructions */
    llvm::SmallVector<llvm::ReturnInst*, 2> returnInstructions;

    /* Instructions that assign a value to the program counter */
    llvm::SmallVector<llvm::StoreInst*, 4> pcAssignments;

    llvm::SmallVector<uint64_t, 2> staticBranchTargets;

    void clear() {
        returnInstructions.clear();
        pcAssignments.clear();
        staticBranchTargets.clear();
    }
};
#endif

class TCGLLVMContextPrivate;
class TCGLLVMContext
{
private:
    TCGLLVMContextPrivate* m_private;

public:
    TCGLLVMContext(llvm::LLVMContext&);
    ~TCGLLVMContext();

    llvm::LLVMContext& getLLVMContext();

    llvm::Module* getModule();
    llvm::ModuleProvider* getModuleProvider();

    llvm::legacy::FunctionPassManager* getFunctionPassManager() const;

#ifdef CONFIG_SYMBEX
    /** Called after linking all helper libraries */
    void initializeHelpers();
    void initializeNativeCpuState();
    bool isInstrumented(llvm::Function *tb);
#endif

    static bool GetStaticBranchTarget(const llvm::BasicBlock *bb, uint64_t *target);

    void generateCode(struct TCGContext *s,
                      struct TranslationBlock *tb);

#ifdef STATIC_TRANSLATOR
    const TCGLLVMTBInfo &getTbInfo() const;
    llvm::Function *createTbFunction(const std::string &name);
    llvm::FunctionType *getTbType();
#endif

};

#endif

#endif

