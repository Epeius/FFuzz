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
#include <exec-all.h>
#include <sysemu.h>
#include <sys/shm.h>
}
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iomanip>
#include <cctype>

#include <algorithm>
#include <fstream>
#include <vector>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>    /**/
#include <errno.h>     /*errno*/
#include <unistd.h>    /*ssize_t*/
#include <sys/types.h>
#include <sys/stat.h>  /*mode_t*/
#include <stdlib.h>

#include "InputEndDetector.h"


namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InputEndDetector, "InputEndDetector plugin", "");

void InputEndDetector::initialize()
{
    m_EndDescriptor = s2e()->getConfig()->getInt(getConfigKey() + ".EndDescriptor", 0xFF);
    m_MinContinuous = s2e()->getConfig()->getInt(getConfigKey() + ".MinContinuous", 5);
    m_CheckInterval = s2e()->getConfig()->getInt(getConfigKey() + ".CheckInterval", 1);


    s2e()->getCorePlugin()->onDisabledFork.connect(sigc::mem_fun(*this, &InputEndDetector::onDisabledFork));
}


void InputEndDetector::onDisabledFork(S2EExecutionState*  originalState, klee::ref<klee::Expr> & Condition)
{
    uint64_t oriID = originalState->getID();
    if (!oriID)
        return;
    DECLARE_PLUGINSTATE(InputEndDetectorState, originalState);
    plgState->updatePCCs(originalState->getPc(), Condition);
}


bool InputEndDetector::isEndChecking(S2EExecutionState* state, uint64_t conditionHS)
{
    DECLARE_PLUGINSTATE(InputEndDetectorState, state);

    if (!plgState->isMinContinuousSet())
        plgState->setMinContinuous(m_MinContinuous);

    if (!plgState->isCheckIntervalSet())
        plgState->setCheckInterval(m_CheckInterval);

    return plgState->isEndChecking(conditionHS);
}


void InputEndDetectorState::updatePCCs(uint64_t pc, klee::ref<klee::Expr> condition)
{
    auto it = m_PCCs.find(pc);
    std::vector<klee::ref<klee::Expr> > _tmp;

    if (it != m_PCCs.end()) {
        _tmp = it->second;
        _tmp.push_back(condition);
        m_PCCs[pc] = _tmp;
    } else {
        _tmp.push_back(condition);
        m_PCCs.insert(std::make_pair(pc, _tmp));
    }
    return;
}

bool InputEndDetectorState::isEndChecking(uint64_t conditionHS)
{
    if (!m_filtered) {
        filterInputEndDetectionInternal();
        m_filtered = true;
    }

    return (m_EDHSs.find(conditionHS) != m_EDHSs.end());
}

void InputEndDetectorState::filterInputEndDetectionInternal()
{
    auto pccit = m_PCCs.begin();
    for ( ; pccit != m_PCCs.end(); pccit++ ) {
        std::vector<klee::ref<klee::Expr> > conditions = pccit->second;
        if (conditions.size() < m_MinContinuous)
            continue;

        std::vector<std::set<uint32_t> > allInputOffs;
        std::set<uint64_t> _hash;
        auto conit = conditions.begin();
        for (; conit != conditions.end(); conit++) {
            klee::ref<klee::Expr> _expr = *conit;
            _hash.insert(_expr.get()->hash());
            std::set<uint32_t> _inputOffs;
            findInputBytes(_expr, _inputOffs);
            allInputOffs.push_back(_inputOffs);
        }

        if (isEndDetection(allInputOffs)) {
            m_EDHSs.insert(_hash.begin(), _hash.end());
            g_s2e->getDebugStream() << "InputEndDetector: Find end detection at " << hexval(pccit->first) << ".\n";
        }

    }
}

bool InputEndDetectorState::isEndDetection(std::vector<std::set<uint32_t> > & allinputoffs)
{
    auto aioit = allinputoffs.begin();
    std::set<uint32_t> _firstSet = *aioit;
    if (_firstSet.size() != m_CheckInterval)
        return false;
    uint32_t preOff = *(_firstSet.begin());

    for (aioit++; aioit != allinputoffs.end(); aioit++) {
        std::set<uint32_t> _curOffs = *aioit;
        if (_curOffs.size() != m_CheckInterval)
            return false;
        uint32_t curOff = *(_curOffs.begin());
        if (curOff - preOff != m_CheckInterval)
            return false;
        else
            preOff = curOff;
    }
    return true;
}

void InputEndDetectorState::findInputBytes(klee::ref<klee::Expr> condition, std::set<uint32_t>& collector)
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

InputEndDetectorState::~InputEndDetectorState()
{
}

PluginState *InputEndDetectorState::clone() const
{
    return new InputEndDetectorState();
}

PluginState *InputEndDetectorState::factory(Plugin *p, S2EExecutionState *s)
{
    InputEndDetectorState *ret = new InputEndDetectorState();
    return ret;
}

} // namespace plugins
} // namespace s2e
