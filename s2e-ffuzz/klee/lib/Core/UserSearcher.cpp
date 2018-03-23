//===-- UserSearcher.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/UserSearcher.h"

#include "klee/Searcher.h"
#include "klee/Executor.h"

#include "llvm/Support/CommandLine.h"

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool>
UseDfsSearch("use-dfs-search");

cl::opt<bool>
UseNonUniformRandomSearch("use-non-uniform-random-search");

cl::opt<bool>
UseRandomPathSearch("use-random-path");

cl::opt<bool>
UseRandomSearch("use-random-search");

cl::opt<bool>
UseBatchingSearch("use-batching-search",
                  cl::desc("Use batching searcher (keep running selected state for N instructions/time, see --batch-instructions and --batch-time"));

//XXX: We disable this option for S2E
//A small number of instructions takes precedence over batch-time
#if 0
cl::opt<unsigned>
BatchInstructions("batch-instructions",
                  cl::desc("Number of instructions to batch when using --use-batching-search"),
                  cl::init(10000));
#endif

cl::opt<double>
BatchTime("batch-time",
          cl::desc("Amount of time to batch when using --use-batching-search"),
          cl::init(1.0));
}


// FIXME: Remove.
bool klee::userSearcherRequiresBranchSequences() {
    return false;
}

Searcher *klee::constructUserSearcher(Executor &executor) {
    Searcher *searcher = 0;

    if (UseRandomSearch) {
        searcher = new RandomSearcher();
    } else if (UseRandomPathSearch) {
        searcher = new RandomPathSearcher(executor);
    } else if (UseDfsSearch) {
        searcher = new DFSSearcher();
    } else {
        searcher = new DFSSearcher();
    }

    if (UseBatchingSearch) {
        //searcher = new BatchingSearcher(searcher, BatchTime, BatchInstructions);
        //XXX: For S2E
        searcher = new BatchingSearcher(searcher, BatchTime, 0);
    }

    llvm::raw_ostream &os = executor.getHandler().getInfoStream();

    os << "BEGIN searcher description\n";
    searcher->printName(os);
    os << "END searcher description\n";

    return searcher;
}
