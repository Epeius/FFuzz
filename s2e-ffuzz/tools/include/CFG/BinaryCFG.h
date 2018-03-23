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

#ifndef S2E_TOOLS_BINARY_CFG_H
#define S2E_TOOLS_BINARY_CFG_H

#include <set>

#include <llvm/ADT/SmallVector.h>

#include "lib/Utils/Utils.h"

namespace llvm {

class BinaryBasicBlock;
class BinaryFunction;

///
/// \brief Models an abstract basic block (non-LLVM).
///
/// Mainly used to feed in basic blocks extracted by IDA Pro.
///
class BinaryBasicBlock {
public:
    enum Type {
        BB_NORMAL,
        BB_CALL,
    };

    /// Unordered list of binary basic blocks.
    typedef SmallVector<BinaryBasicBlock*, 4> Children;

    // Binary basic block iterators
    typedef Children::iterator succ_iterator;
    typedef Children::const_iterator const_succ_iterator;
    typedef Children::iterator pred_iterator;
    typedef Children::const_iterator const_pred_iterator;

private:
    // Keep track of the predecessor/successor basic blocks
    Children successors;
    Children predecessors;

    /// Address of the basic block's first instruction.
    uint64_t startPc;

    /// Address of the basic block's last instruction.
    uint64_t endPc;

    /// Size of the basic block.
    unsigned size;

    /// Basic block type.
    Type type;

    /// Only valid for call instructions.
    uint64_t targetPc;

public:
    /// Create a normal basic block.
    BinaryBasicBlock(uint64_t start, uint64_t end, unsigned s) :
            startPc(start), endPc(end), size(s), type(BB_CALL), targetPc(0) { }

    /// Create a call basic block.
    BinaryBasicBlock(uint64_t start, uint64_t end, unsigned s, uint64_t target) :
            startPc(start), endPc(end), size(s), type(BB_CALL), targetPc(target) { }

    /// Create a normal basic block with the given start address.
    BinaryBasicBlock(uint64_t start) :
            BinaryBasicBlock(start, 0, 0) { }

    /// Create an empty, normal basic block.
    BinaryBasicBlock() : BinaryBasicBlock(0) { }

    void addSucc(BinaryBasicBlock* BB);

    void addPred(BinaryBasicBlock* BB);

    uint64_t getStartPc() const;

    uint64_t getEndPc() const;

    unsigned getSize() const;

    Type getType() const;

    bool isCall() const;

    uint64_t getTargetPc() const;

    // Printing method used by LoopInfo
    void printAsOperand(raw_ostream& OS, bool printType=true) const;

    succ_iterator succ_begin();

    succ_iterator succ_end();

    const_succ_iterator succ_begin() const;

    const_succ_iterator succ_end() const;

    unsigned numSuccessors() const;

    unsigned numPredecessors() const;

    pred_iterator pred_begin();

    pred_iterator pred_end();

    const_pred_iterator pred_begin() const;

    const_pred_iterator pred_end() const;
};

///
/// \brief An ordered set of binary basic blocks.
///
/// The basic blocks are ordered by their start addresses.
///
class BinaryBasicBlocks {
private:
    // Used for ordering binary basic blocks within a function
    struct BBByAddress {
        bool operator()(const BinaryBasicBlock* LHS, const BinaryBasicBlock* RHS) const {
            return LHS->getStartPc() < RHS->getStartPc();
        }
    };

    std::set<BinaryBasicBlock*, BBByAddress> basicBlocks;

public:
    // Binary basic blocks iterators
    typedef std::set<BinaryBasicBlock*, BBByAddress>::iterator iterator;
    typedef std::set<BinaryBasicBlock*, BBByAddress>::const_iterator const_iterator;

    ///
    /// \brief Find a basic block with the given start address.
    ///
    /// \param Start address of the basic block to find
    /// \return A pointer to the basic block if it is found, or \c NULL
    /// otherwise
    ///
    BinaryBasicBlock* find(uint64_t startPc);

    void insert(BinaryBasicBlock* BB);

    unsigned size() const;

    iterator begin();

    iterator end();

    const_iterator begin() const;

    const_iterator end() const;
};

///
/// \brief A function is a collection of basic blocks and an entry point.
///
class BinaryFunction {
public:
    // Binary function iterators
    typedef BinaryBasicBlocks::iterator iterator;
    typedef BinaryBasicBlocks::const_iterator const_iterator;

private:
    BinaryBasicBlocks nodes;
    std::string name;
    BinaryBasicBlock* entry;

public:
    /// Create an empty function.
    BinaryFunction(std::string n) : name(n) { }

    /// Create a function with an entry node.
    BinaryFunction(std::string n, BinaryBasicBlock* e);

    BinaryBasicBlock* getEntryBlock() const;

    void setEntryBlock(BinaryBasicBlock* BB);

    std::string getName() const;

    void rename(const std::string& n);

    unsigned size() const;

    iterator begin();

    iterator end();

    const_iterator begin() const;

    const_iterator end() const;

    void add(BinaryBasicBlock* BB);

    void add(BinaryBasicBlock* BB, const BinaryBasicBlock::Children& succs);
};

/// Ordered set of binary functions.
typedef std::set<BinaryFunction*> BinaryFunctions;

} // namespace llvm

#endif
