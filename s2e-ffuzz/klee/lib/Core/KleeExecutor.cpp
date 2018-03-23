#include "KleeExecutor.h"
#include "klee/SolverFactory.h"

using namespace klee;

KleeExecutor::KleeExecutor(const InterpreterOptions &opts, InterpreterHandler *ie, llvm::LLVMContext& context)
        : Executor(opts, ie, new DefaultSolverFactory(ie), context)
{
}

///

Interpreter *Interpreter::createKleeExecutor(const InterpreterOptions &opts,
                                 InterpreterHandler *ih,
                                 llvm::LLVMContext& context) {
  return new KleeExecutor(opts, ih, context);
}
