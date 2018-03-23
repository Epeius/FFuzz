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

#ifndef S2E_TOOLS_GRAPH_H
#define S2E_TOOLS_GRAPH_H

#include <vector>

#include <llvm/ADT/GraphTraits.h>
#include <llvm/Support/DOTGraphTraits.h>

#include "BinaryCFG.h"

namespace llvm {

///
/// \brief Specialized BinaryFunction for use by the \c GraphTraits struct.
///
/// The \c GraphTraits \c nodes_iterator does not play nicely with \c std::set
/// (which is what \c BinaryFunction uses internally), so the \c set gets
/// transformed into a \c vector for use by the \c GraphTraits struct.
///
class BinaryFunctionGT {
public:
    typedef std::vector<BinaryBasicBlock> BinaryBasicBlocks;

    // Binary function iterators
    typedef BinaryBasicBlocks::iterator iterator;
    typedef BinaryBasicBlocks::const_iterator const_iterator;

private:
    /// A vector of binary basic blocks to iterate over.
    mutable BinaryBasicBlocks BBs;

    /// Wrapped binary function.
    const BinaryFunction *F;

    void updateBasicBlocks() const {
        BBs.clear();

        for (auto it = F->begin(); it != F->end(); ++it) {
            BBs.push_back(**it);
        }
    }

public:
    /// Wrap a binary function.
    BinaryFunctionGT(const BinaryFunction *BF) : F(BF) { }

    BinaryBasicBlock *getEntryBlock() const {
        return F->getEntryBlock();
    }

    std::string getName() const {
        return F->getName();
    }

    unsigned size() const {
        return F->size();
    }

    iterator begin() {
        updateBasicBlocks();

        return BBs.begin();
    }

    iterator end() {
        updateBasicBlocks();

        return BBs.end();
    }

    const_iterator begin() const {
        updateBasicBlocks();

        return BBs.begin();
    }

    const_iterator end() const {
        updateBasicBlocks();

        return BBs.end();
    }
};

// Provide specializations of GraphTraits to be able to treat a BinaryFunction
// as a graph of BinaryBasicBlocks.

template<> struct GraphTraits<BinaryBasicBlock*> {
    typedef BinaryBasicBlock NodeType;
    typedef NodeType *NodeRef;
    typedef BinaryBasicBlock::succ_iterator ChildIteratorType;

    static NodeRef getEntryNode(NodeRef BB) {
        return BB;
    }

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->succ_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->succ_end();
    }
};

template<> struct GraphTraits<const BinaryBasicBlock*> {
    typedef const BinaryBasicBlock NodeType;
    typedef const NodeType *NodeRef;
    typedef BinaryBasicBlock::const_succ_iterator ChildIteratorType;

    static NodeRef getEntryNode(NodeRef BB) {
        return BB;
    }

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->succ_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->succ_end();
    }
};

// Provide specializations of GraphTraits to be able to treat a BinaryFunction
// as a graph of BinaryBasicBlocks and to walk it in inverse order. Inverse
// order for a function is considered to be when traversing the predecessor
// edges of a BinaryBasicBlock instead of the successor edges.

template<> struct GraphTraits<Inverse<BinaryBasicBlock*> > {
    typedef BinaryBasicBlock NodeType;
    typedef NodeType *NodeRef;
    typedef BinaryBasicBlock::pred_iterator ChildIteratorType;

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->pred_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->pred_end();
    }
};

template<> struct GraphTraits<Inverse<const BinaryBasicBlock*> > {
    typedef const BinaryBasicBlock NodeType;
    typedef const NodeType *NodeRef;
    typedef BinaryBasicBlock::const_pred_iterator ChildIteratorType;

    static inline ChildIteratorType child_begin(NodeRef BB) {
        return BB->pred_begin();
    }

    static inline ChildIteratorType child_end(NodeRef BB) {
        return BB->pred_end();
    }
};

// Provide specializations of GraphTraits to be able to treat a binary function
// as a graph of binary basic block... these are the same as the binary basic
// block iterators, except that the root node is implicitly the first node of
// the function.

template<> struct GraphTraits<BinaryFunctionGT*> :
        public GraphTraits<BinaryBasicBlock*> {
    static NodeRef getEntryNode(BinaryFunctionGT *F) {
        return F->getEntryBlock();
    }

    typedef BinaryFunctionGT::iterator nodes_iterator;

    static nodes_iterator nodes_begin(BinaryFunctionGT *F) {
        return F->begin();
    }

    static nodes_iterator nodes_end(BinaryFunctionGT *F) {
        return F->end();
    }

    static unsigned size(BinaryFunctionGT *F) {
        return F->size();
    }
};

template<> struct GraphTraits<const BinaryFunctionGT*> :
        public GraphTraits<const BinaryBasicBlock*> {
    static NodeRef getEntryNode(const BinaryFunctionGT *F) {
        return F->getEntryBlock();
    }

    typedef BinaryFunctionGT::const_iterator nodes_iterator;

    static nodes_iterator nodes_begin(const BinaryFunctionGT *F) {
        return F->begin();
    }

    static nodes_iterator nodes_end(const BinaryFunctionGT *F) {
        return F->end();
    }

    static unsigned size(const BinaryFunctionGT *F) {
        return F->size();
    }
};

// Specialized struct to convert a binary function to a DOT graph.
template<> struct DOTGraphTraits<BinaryFunctionGT*> :
        public DefaultDOTGraphTraits {
    DOTGraphTraits(bool simple=false) : DefaultDOTGraphTraits(simple) { }

    static std::string getGraphName(BinaryFunctionGT *F) {
        return F->getName();
    }

    std::string getNodeLabel(BinaryBasicBlock *BB, BinaryFunctionGT *F) {
        std::stringstream SS;
        SS << std::hex << BB->getStartPc();

        return SS.str();
    }

    static std::string getNodeAttributes(BinaryBasicBlock *BB, BinaryFunctionGT *F) {
        if (BB->isCall()) {
            return "color=red";
        } else {
            return "";
        }
    }
};

} // namespace llvm

#endif
