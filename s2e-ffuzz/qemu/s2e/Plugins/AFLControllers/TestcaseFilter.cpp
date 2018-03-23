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
 * Written by Bin Zhang <bin.zhang@epfl.ch>
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <tcg.h>
#include <tcg-llvm.h>
#include <exec-all.h>
#include <ioport.h>
#include <sysemu.h>
#include <cpus.h>
#include <qemu-timer.h>
#include <qlist.h>
#include <qint.h>
}

#include <llvm/Support/Path.h>
#include <llvm/Support/FileSystem.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EStatsTracker.h>
#include <klee/util/Assignment.h>
#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/TreeStream.h"

#include <iostream>
#include <sstream>
#include <unistd.h>
#include <stdlib.h>
#include <fstream>

#include "TestcaseFilter.h"
#include "FileLock.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TestcaseFilter, "FuzzyS2E plugin", "");

void TestcaseFilter::initialize()
{
    bool ok = false;
    m_hottestNum = s2e()->getConfig()->getInt(getConfigKey() + ".hottestNum", 100);
    m_sampleFreq = s2e()->getConfig()->getInt(getConfigKey() + ".sampleFreq", 100);
    m_FreqCounter = m_sampleFreq;
    m_collectOffs = s2e()->getConfig()->getBool(getConfigKey() + ".collectOffs",
            false, &ok);


    if (m_collectOffs) {
        std::stringstream offs_strstream;
        offs_strstream << OFFSDIR;
        if (::access(offs_strstream.str().c_str(), F_OK)) // for all testcases
            mkdir(offs_strstream.str().c_str(), 0777);
    }
    m_ModeSwitched = false;
    if (m_collectOffs) {
        m_IED = static_cast<InputEndDetector*>(s2e()->getPlugin("InputEndDetector"));
        if (!m_IED) {
            std::cerr << "Could not find InputEndDetector plug-in. " << '\n';
            exit(0);
        }
    }

    s2e()->getCorePlugin()->onDisabledFork.connect(sigc::mem_fun(*this, &TestcaseFilter::onDisabledFork));
}

void TestcaseFilter::displayHD()
{
    std::ofstream outfile;

    outfile.open("/tmp/hot_degree", std::ios_base::app);
    uint32_t i = 1;
    for (; i <= m_hottestNum; i++) {
        auto it = m_sigID_HD.find(i);
        if (it == m_sigID_HD.end())
            outfile << "0" << " ";
        else
            outfile << it->second << " ";
    }
    outfile << "\n";
    outfile.close();
}

bool TestcaseFilter::addSigState(S2EExecutionState* state) {
    // verbose output
    if (m_sigID_States.size()+1 >= m_hottestNum) { // do not add more to control memory overhead
        m_sigID_ConInMainImage.erase(state->getID());
        return true;
    }

    s2e()->getDebugStream() << "TestcaseFilter: adding state[" << state->getID() << "] to significant states, its"
            "constraints are: \n";

    std::set<klee::ref<klee::Expr> > PC = state->constraints.getConstraintSet();
    std::set<uint64_t> hashes;
    auto pcit = PC.begin();
    for (; pcit != PC.end(); pcit++) {
        klee::ref<klee::Expr> tmp = (*pcit);
        tmp.get()->print(s2e()->getDebugStream());
        unsigned hashval = tmp.get()->hash();
        s2e()->getDebugStream() << "\nIts hash is " << hashval << "\n";
        hashes.insert(hashval);
    }

    auto hsit = hashes.begin();
    s2e()->getDebugStream() << "-----------------------------------------------------\n";
    for (; hsit != hashes.end(); hsit++){
        s2e()->getDebugStream() << *hsit << "\n";
    }
    s2e()->getDebugStream() << "-----------------------------------------------------\n";

    uint32_t inputsize = state->getInputSize();

    auto ssit = m_sigID_States.begin();
    for (; ssit != m_sigID_States.end(); ssit++) {
        S2EExecutionState* current = static_cast<S2EExecutionState*>(ssit->second);
        if (current->getInputSize() != inputsize)
            continue;
        std::set<uint64_t> currentHashes = m_sigID_ConHash[current->getID()];
        if (currentHashes == hashes){
            s2e()->getDebugStream()<< "TestcaseFilter: found need merged states, len is " << inputsize << ".\n";
            m_sigID_ConInMainImage.erase(state->getID());
            return true;
        }
    }


    m_sigID_ConHash.insert(std::make_pair(state->getID(), hashes)); // Use hash value to evaluate expression quickly
    m_sigID_HD.insert(std::make_pair(state->getID(), 0)); // initial hot degree to zero
    m_sigID_States.insert(std::make_pair(state->getID(), state));

    if (m_input_states.find(inputsize) == m_input_states.end()){
        std::set<S2EExecutionState* > tmp;
        tmp.insert(state);
        m_input_states.insert(std::make_pair(inputsize, tmp));
    } else {
        m_input_states[inputsize].insert(state);
    }
    if (m_collectOffs)
        CollectSignificantOffs(state);
    return false;

}

// Only collect the constraint in main module
void TestcaseFilter::onDisabledFork(S2EExecutionState* originalState, klee::ref<klee::Expr> & Condition)
{
    if (!isMainImage(originalState->getPc()))
        return;

    g_s2e->getDebugStream() << "Taint fork state[" << originalState->getID() << "] at " <<
                    hexval(originalState->getPc()) << ".\nCurrent condition is; \n";

    Condition.get()->print(g_s2e->getDebugStream());
    g_s2e->getDebugStream() << "\n";

    uint64_t id = originalState->getID();

    auto it = m_sigID_ConInMainImage.find(id);

    if (it == m_sigID_ConInMainImage.end()) {
        PathConstraint _pc;
        _pc.insert(Condition);
        m_sigID_ConInMainImage.insert(std::make_pair(id, _pc));
    } else {
        PathConstraint _pc = it->second;
        _pc.insert(Condition);
        m_sigID_ConInMainImage[id] = _pc;
    }
}

bool TestcaseFilter::filterSplitedStateFast(S2EExecutionState* state,
                                            std::set<uint64_t>& vH_T,
                                            std::set<uint64_t>& vH_F,
                                            bool& redundant)
{
    std::set<uint64_t> currentHashes = m_sigID_ConHash[state->getID()];


    auto Fit = vH_F.begin();

    // Verify false first
    for (; Fit != vH_F.end(); Fit++) {
        if (currentHashes.find(*Fit) != currentHashes.end())
            return true;
    }

    // then move on to verify true
    auto Tit = currentHashes.begin();
    for (; Tit != currentHashes.end(); Tit++) {
        if (vH_T.find(*Tit) == vH_T.end()){
            redundant = false;
            return false;
        }
    }


    redundant = true;
    return false;
}


//TODO: Break this function into smaller ones.
bool TestcaseFilter::isRedundant(const char* filename, bool* need_symbex)
{
    if(!m_sigID_States.size())
        return false;
    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        g_s2e->getDebugStream() << "TestcaseFilter: could not open " <<  filename << "\n";
        char err[128];
        sprintf(err, "errno.%d is: %s/n", errno, strerror(errno));
        s2e()->getDebugStream() << err << "\n";
        exit(-1);
    }
    off_t filesize = lseek(fd, 0, SEEK_END); // get size
    if(filesize < 0){
        g_s2e->getDebugStream() << "Bad file\n";
        close(fd);
        exit(-1);
    }

    bool redundant = false;
    uint64_t actVerified = 0;
    klee::WallTimer* timer = new klee::WallTimer();

    std::set<uint64_t> verHashes_T; // for verified TRUE
    std::set<uint64_t> verHashes_F; // for verified FALSE


    std::set<S2EExecutionState*> allSameLenState = m_input_states[filesize];

    auto it = allSameLenState.begin();

    for (; it != allSameLenState.end(); it++) {
        S2EExecutionState* current = (*it);

        bool testRedundant = false;
        if (filterSplitedStateFast(current, verHashes_T, verHashes_F, testRedundant)){
            s2e()->getDebugStream() << "find false hash, continue.\n";
            continue;
        }

        if (testRedundant) {
            redundant = testRedundant;
            s2e()->getDebugStream() << "Verified to same path as state " << current->getID() << "\n";
            m_sigID_HD[current->getID()] += 1;
            goto cleanup;
        }

        actVerified++;

        std::vector<const klee::Array*> symbObjects;
        std::vector<std::vector<unsigned char> > concreteObjects;
        auto bindit = current->concolics->bindings.begin();

        for (; bindit != current->concolics->bindings.end(); bindit++) {
            const klee::Array* arr = (*bindit).first;
            symbObjects.push_back(arr);
            if (strstr(arr->getName().c_str(), "const_arr") || strstr(arr->getName().c_str(), "dummy")) {
                concreteObjects.push_back((*bindit).second);
            }
            else {
                std::vector<unsigned char> concreteData;
                for (unsigned i = 0; i< filesize; ++i) {
                    uint8_t byte = 0;
                    lseek(fd, i, SEEK_SET);
                    if (::read(fd, &byte, 1) <= 0) {
                        close(fd);
                        s2e()->getDebugStream() << "TestcaseFilter: Significant testcase because could bit readfile.\n";
                        return false;
                    }
                    concreteData.push_back(byte);
                }
                concreteObjects.push_back(concreteData);
            }
        }
        current->concolics->clear();
        for (unsigned i = 0; i < symbObjects.size(); ++i) {
            current->concolics->add(symbObjects[i], concreteObjects[i]);
        }

        std::set<klee::ref<klee::Expr> > PC = m_sigID_ConInMainImage[current->getID()];
        auto CMIit = m_sigID_ConInMainImage.find(current->getID());
        if(CMIit == m_sigID_ConInMainImage.end()) {
            s2e()->getDebugStream() << "TestcaseFilter: cannot find state: " << current->getID() << " in m_sigID_ConInMainImage\n";
            exit(-1);
        }

        if (!PC.size()){
            s2e()->getDebugStream() << "TestcaseFilter: verifying state: " << current->getID() << " has no pc\n";
        }
        auto pcit = PC.begin();
        for (; pcit != PC.end(); pcit++) {
            /* Fast check whether we have evaluated this expression before */
            uint64_t hash = (*pcit).get()->hash();
            if (verHashes_T.find(hash) != verHashes_T.end())
                continue;
            if (verHashes_F.find(hash) != verHashes_F.end())
                break;

            klee::ref<klee::Expr> evalResult = current->concolics->evaluate(*pcit);
            klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(evalResult);
            if (!ce) {
                s2e()->getDebugStream() << "Could not evaluate the following expression to a constant.\n";
                evalResult.get()->print(s2e()->getDebugStream());
                s2e()->getDebugStream() << "\n";
                close(fd);
                bool ret = (bool)(rand() % 5);
                if (ret) {
                    s2e()->getDebugStream() << "Verified to same path as state " << current->getID() << "\n";
                    m_sigID_HD[current->getID()] += 1;
                }
                return (ret);
            }
            bool conditionIsTrue = ce->isTrue();
            if (conditionIsTrue) {
                verHashes_T.insert(hash);
                continue;
            } else {
                verHashes_F.insert(hash);
                break;
            }
        }

        redundant = pcit == PC.end();
        if (redundant){ // determined to be redundant
            s2e()->getDebugStream() << "Verified to same path as state " << current->getID() << "\n";
            m_sigID_HD[current->getID()] += 1;
            break;
        }
        else
            s2e()->getDebugStream() << "evaluated false, continue.\n";
    }

    if (!redundant){
        if (m_ModeSwitched) {
            if (!m_FreqCounter--) {
                m_FreqCounter = m_sampleFreq;
                *need_symbex = updateHotStates();
            }
        }
    }


cleanup:
    uint64_t ellapseTime = timer->check();
    s2e()->getDebugStream() << "TestcaseFilter: Currently has " << m_sigID_States.size() << " states need to verify and " << allSameLenState.size() << " same"
                                                                                                                        " file-len states.\n";
    s2e()->getDebugStream() << "TestcaseFilter: Evaluation has tried for " << actVerified << "states, and costs " << ellapseTime << " us\n";
    close(fd);
    delete timer;
    return redundant;
}


void TestcaseFilter::simpSigStates(uint64_t id)
{

}

bool TestcaseFilter::checkLoopBucketFast(S2EExecutionState* _state, uint64_t hitcount)
{
    klee::WallTimer* timer = new klee::WallTimer();
    std::set<LoopBucket*> LBs = m_dril_inputsizeLB[_state->getInputSize()];
    auto lbit = LBs.begin();
    LoopBucket* lb = NULL;
    bool findit = false;
    uint64_t curPC = _state->getPc();
    for (; lbit != LBs.end(); lbit++){
        if ((*lbit)->pc == curPC) {
            lb = *lbit;
            findit = true;
            break;
        }
    }

    if (!lb) { // if not find, create a new loop bucket and insert it
        lb = new LoopBucket(curPC);
        LBs.insert(lb);
        m_dril_inputsizeLB[_state->getInputSize()] = LBs;
    }

    uint64_t ellapseTime = timer->check();
    s2e()->getDebugStream() << "TestcaseFilter: Checking loops costs " << ellapseTime << " us, and loop's hitcount is " <<
            hitcount << ".\n" ;

    if (hitcount == 0) {
        if (lb->buckets[0])
            return true;
        else {
            lb->buckets[0] = true;
            return false;
        }
    } else if (hitcount == 1) {
        if (lb->buckets[1])
            return true;
        else {
            lb->buckets[1] = true;
            return false;
        }
    } else if (hitcount == 2) {
        if (lb->buckets[2])
            return true;
        else {
            lb->buckets[2] = true;
            return false;
        }
    } else if (hitcount == 3 || hitcount == 4) {
        if (lb->buckets[3])
            return true;
        else {
            lb->buckets[3] = true;
            return false;
        }
    } else if (hitcount >= 5 && hitcount <= 8) {
        if (lb->buckets[4])
            return true;
        else {
            lb->buckets[4] = true;
            return false;
        }
    } else if (hitcount >= 9 && hitcount <= 16) {
        if (lb->buckets[5])
            return true;
        else {
            lb->buckets[5] = true;
            return false;
        }
    } else if (hitcount >= 17 && hitcount <= 32) {
        if (lb->buckets[6])
            return true;
        else {
            lb->buckets[6] = true;
            return false;
        }
    } else if (hitcount >= 33 and hitcount <= 64) {
        if (lb->buckets[7])
            return true;
        else {
            lb->buckets[7] = true;
            return false;
        }
    } else if (hitcount >= 65 and hitcount <= 128) {
        if (lb->buckets[8])
            return true;
        else {
            lb->buckets[8] = true;
            return false;
        }
    } else if (hitcount >= 129 and hitcount <= 256) {
        if (lb->buckets[9])
            return true;
        else {
            lb->buckets[9] = true;
            return false;
        }
    } else {
        if (lb->buckets[10])
            return true;
        else {
            lb->buckets[10] = true;
            return false;
        }
    }
}

bool TestcaseFilter::checkRedundantFast(S2EExecutionState* _state, uint64_t hitcount)
{
    klee::ref<klee::Expr> lastCondition = *(_state->constraints.begin());
    s2e()->getDebugStream() << "last added is :\n";
    lastCondition.get()->print(s2e()->getDebugStream());

    uint64_t lastHS = lastCondition.get()->hash();

    if (checkLoopBucketFast(_state, hitcount)) {
        s2e()->getDebugStream() << "TestcaseFilter: ignore loop, not generate!\n";
        return true;
    }

    if(m_drill_ConHash[_state->getInputSize()].find(lastHS) !=
            m_drill_ConHash[_state->getInputSize()].end())
        return true;


    std::set<S2EExecutionState* > allSamelenStates = m_input_states[_state->getInputSize()];

    auto it = allSamelenStates.begin();
    for (; it != allSamelenStates.end(); it++) {
        S2EExecutionState* _tmp = *it;
        if (m_sigID_ConHash[_tmp->getID()].find(lastHS) != m_sigID_ConHash[_tmp->getID()].end())
            return true;
    }

    m_drill_ConHash[_state->getInputSize()].insert(lastHS);

    return false;
}

bool TestcaseFilter::updateHotStates()
{

    bool touched = false;
    uint64_t touchedID;
    // reset all hot states' hot degree
    for (auto hdit = m_sigID_HD.begin(); hdit != m_sigID_HD.end(); hdit++) {
        if (!touched) {
            if (hdit->second == 0) {
                touchedID = hdit->first;
                touched   = true;
            }
        }
        hdit->second = 0;
    }

    if (!touched) // all states are hit, ignore
        return touched;
    // clean ups, remove the state and determine whether need to symbex again.

    m_sigID_ConHash.erase(touchedID);
    m_sigID_HD.erase(touchedID);

    S2EExecutionState* unhotState = m_sigID_States[touchedID];
    std::set<S2EExecutionState*> allSameLenState = m_input_states[unhotState->getInputSize()];
    allSameLenState.erase(allSameLenState.find(unhotState));
    m_input_states[unhotState->getInputSize()] = allSameLenState;

    m_sigID_States.erase(touchedID);
    m_sigID_ConInMainImage.erase(touchedID);
    s2e()->getExecutor()->terminateStateEarly(*unhotState, "un-hot states!");
    return touched;
}

void TestcaseFilter::cleanup(uint64_t touchedID)
{
    // clean ups, remove the state and determine whether need to symbex again.
    m_sigID_ConInMainImage.erase(touchedID);
}


/*
 * Ending detection of the input may set all the bytes as significant offsets.
 * So far, there are two options.
 * 1: Use manual configuration to filter these detection codes.
 * 2: Use lazy determination to identify these significant offsets. ** Done on AFL side.
 */
void TestcaseFilter::CollectSignificantOffs(S2EExecutionState* state)
{
    if (state->getInputSize() < m_IED->getMinContinuous())
        return;
    std::set<uint32_t> sigOffset;
    std::set<klee::ref<klee::Expr> > PC = state->constraints.getConstraintSet();
    auto pcit = PC.begin();
    for (; pcit != PC.end(); pcit++) {
        klee::ref<klee::Expr> condition = *pcit;
        s2e()->getDebugStream() << "TestcaseFilter: collecting " << condition.get()->hash() << "\n";
        //FIXME: condition hash is different with forking contidition hash
        if (m_IED->isEndChecking(state, condition.get()->hash()))
            continue;
        findInputBytes(condition, sigOffset);
    }

    if (!sigOffset.size())
        return;

    std::stringstream offs_strstream;
    offs_strstream << OFFSDIR << "/" << state->getInputSize() << ".off";

    int fd = open(offs_strstream.str().c_str(), O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        s2e()->getDebugStream() << "TestcaseFilter: Cannot open offset file: " << offs_strstream.str() << " to write collected offsets.\n";
        char err[128];
        sprintf(err, "errno.%d is: %s/n", errno, strerror(errno));
        s2e()->getDebugStream() << err << "\n";
        close(fd);
        exit(-1);
    }
    writew_lock(fd);
    auto offit = sigOffset.begin();
    for (; offit != sigOffset.end(); offit++) {
        char off_str[32];
        memset(off_str, 0, sizeof(off_str));
        sprintf(off_str, "%d-", *offit);
        s2e()->getDebugStream() << "TestcaseFilter: Writing " << *offit << "\n";
        if (0 > write(fd, off_str, strlen(off_str)))
            exit(-1);
    }
    unlock(fd);
    close(fd);
}

// replace the ReadExpr with Constant from file
void TestcaseFilter::findInputBytes(klee::ref<klee::Expr> condition, std::set<uint32_t>& collector)
{
    uint8_t kidsnum = condition.get()->getNumKids();
    uint8_t grandsons = 0;
    while(grandsons < kidsnum){
        klee::ref<klee::Expr> grandson = condition.get()->getKid(grandsons);
        if(grandson.get()->getKind() == klee::Expr::Read){
            klee::ReadExpr *_readExpr = dyn_cast<klee::ReadExpr>(grandson);
            klee::ref<klee::Expr> _readindex = _readExpr->getIndex();
            klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(_readindex);
            if (!ce) {
                break; // ignore
            }
            off_t index = ce->getZExtValue();
            collector.insert((uint32_t)index);
        } else {
            findInputBytes(grandson, collector);
        }
        grandsons++;
    }
}

TestcaseFilter::~TestcaseFilter()
{
    // clean up to release memories
    auto it = m_touched_symSize_PC.begin();
    for (; it != m_touched_symSize_PC.end(); it++) {
        delete *it;
    }
}

} // namespace plugins
} // namespace s2e
