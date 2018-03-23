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

#include "CFG/BinaryCFG.h"

namespace llvm {

void BinaryBasicBlock::addSucc(BinaryBasicBlock* BB) {
    successors.push_back(BB);
}

void BinaryBasicBlock::addPred(BinaryBasicBlock* BB) {
    predecessors.push_back(BB);
}

uint64_t BinaryBasicBlock::getStartPc() const {
    return startPc;
}

uint64_t BinaryBasicBlock::getEndPc() const {
    return endPc;
}

unsigned BinaryBasicBlock::getSize() const {
    return size;
}

BinaryBasicBlock::Type BinaryBasicBlock::getType() const {
    return type;
}

bool BinaryBasicBlock::isCall() const {
    return type == BB_CALL;
}

uint64_t BinaryBasicBlock::getTargetPc() const {
    return targetPc;
}

void BinaryBasicBlock::printAsOperand(raw_ostream& OS, bool printType) const {
    OS << "BB(" << hexval(startPc) << "," << hexval(endPc) << ")";
}

BinaryBasicBlock::succ_iterator BinaryBasicBlock::succ_begin() {
    return successors.begin();
}

BinaryBasicBlock::succ_iterator BinaryBasicBlock::succ_end() {
    return successors.end();
}

BinaryBasicBlock::const_succ_iterator BinaryBasicBlock::succ_begin() const {
    return successors.begin();
}

BinaryBasicBlock::const_succ_iterator BinaryBasicBlock::succ_end() const {
    return successors.end();
}

unsigned BinaryBasicBlock::numSuccessors() const {
    return successors.size();
}

unsigned BinaryBasicBlock::numPredecessors() const {
    return predecessors.size();
}

BinaryBasicBlock::pred_iterator BinaryBasicBlock::pred_begin() {
    return predecessors.begin();
}

BinaryBasicBlock::pred_iterator BinaryBasicBlock::pred_end() {
    return predecessors.end();
}

BinaryBasicBlock::const_pred_iterator BinaryBasicBlock::pred_begin() const {
    return predecessors.begin();
}

BinaryBasicBlock::const_pred_iterator BinaryBasicBlock::pred_end() const {
    return predecessors.end();
}

///////////////////////////////////////////////////////////////////////////////

BinaryBasicBlock* BinaryBasicBlocks::find(uint64_t startPc) {
    BinaryBasicBlock dummy(startPc);
    iterator bbIt = basicBlocks.find(&dummy);

    if (bbIt == basicBlocks.end()) {
        return NULL;
    } else {
        return *bbIt;
    }
}

void BinaryBasicBlocks::insert(BinaryBasicBlock* BB) {
    basicBlocks.insert(BB);
}

unsigned BinaryBasicBlocks::size() const {
    return basicBlocks.size();
}

BinaryBasicBlocks::iterator BinaryBasicBlocks::begin() {
    return basicBlocks.begin();
}

BinaryBasicBlocks::iterator BinaryBasicBlocks::end() {
    return basicBlocks.end();
}

BinaryBasicBlocks::const_iterator BinaryBasicBlocks::begin() const {
    return basicBlocks.begin();
}

BinaryBasicBlocks::const_iterator BinaryBasicBlocks::end() const {
    return basicBlocks.end();
}

///////////////////////////////////////////////////////////////////////////////

BinaryFunction::BinaryFunction(std::string n, BinaryBasicBlock* e) :
        name(n), entry(e) {
    if (e) {
        nodes.insert(e);
    }
}

BinaryBasicBlock* BinaryFunction::getEntryBlock() const {
    return entry;
}

void BinaryFunction::setEntryBlock(BinaryBasicBlock* BB) {
    entry = BB;
}

std::string BinaryFunction::getName() const {
    return name;
}

void BinaryFunction::rename(const std::string& n) {
    name = n;
}

unsigned BinaryFunction::size() const {
    return nodes.size();
}

BinaryFunction::iterator BinaryFunction::begin() {
    return nodes.begin();
}

BinaryFunction::iterator BinaryFunction::end() {
    return nodes.end();
}

BinaryFunction::const_iterator BinaryFunction::begin() const {
    return nodes.begin();
}

BinaryFunction::const_iterator BinaryFunction::end() const {
    return nodes.end();
}

void BinaryFunction::add(BinaryBasicBlock* BB) {
    nodes.insert(BB);
}

void BinaryFunction::add(BinaryBasicBlock* BB,
        const BinaryBasicBlock::Children& succs) {
    for (BinaryBasicBlock* succ : succs) {
        succ->addPred(BB);
        BB->addSucc(succ);
    }

    nodes.insert(BB);
}

} // namespace llvm
