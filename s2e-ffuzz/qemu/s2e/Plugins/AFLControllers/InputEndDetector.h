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

#ifndef INPUTENDDETECTOR_H_
#define INPUTENDDETECTOR_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>

#include <vector>
#include <set>
#include <map>
#include "klee/util/ExprEvaluator.h"
#include <llvm/Support/TimeValue.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>


#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/TreeStream.h"
#include "klee/Internal/Support/Timer.h"

using namespace llvm::sys;

/*
 * Input data end detection in the target program could treat all the offsets of
 * the input data as interesting, which makes selective fuzzing test useless.
 *
 * InputEndDetector is used to detect this detection code in binary.
 */
namespace s2e {
namespace plugins{

class InputEndDetector;

class InputEndDetectorState : public PluginState
{
    /* Type definition */
    // collect all conditions of a specified pc
    typedef std::map<uint64_t, std::vector<klee::ref<klee::Expr> > > PC_Conditions;
    typedef std::set<uint64_t> EndDetectionHashes;
private:
    PC_Conditions m_PCCs;
    EndDetectionHashes m_EDHSs;

    bool m_filtered;
    uint32_t m_MinContinuous;
    uint32_t m_CheckInterval;

private:
    void filterInputEndDetectionInternal();
    void findInputBytes(klee::ref<klee::Expr> condition, std::set<uint32_t>& collector);
    bool isEndDetection(std::vector<std::set<uint32_t> > &);

public:
    InputEndDetectorState() { m_filtered = false; m_MinContinuous = 0; m_CheckInterval = 0;}
    virtual ~InputEndDetectorState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void updatePCCs(uint64_t, klee::ref<klee::Expr>);
    bool isEndChecking(uint64_t /* condition hash */);

    inline bool isMinContinuousSet() { return m_MinContinuous; }
    void setMinContinuous(uint32_t _min) { m_MinContinuous = _min; }

    inline bool isCheckIntervalSet() { return m_CheckInterval; }
    void setCheckInterval(uint32_t _interval) { m_CheckInterval = _interval; }

    friend class InputEndDetector;
};

class InputEndDetector : public Plugin
{
public:

    S2E_PLUGIN


private:
    uint8_t m_EndDescriptor; // such as 0xFF
    uint32_t m_MinContinuous;
    uint32_t m_CheckInterval;

private:
    void onDisabledFork(S2EExecutionState* /* originalState */,
                         klee::ref<klee::Expr> & /* Condition */);

public:
    InputEndDetector(S2E* s2e) : Plugin(s2e) { };

    void initialize();
    bool isEndChecking(S2EExecutionState* /* state */, uint64_t /* condition hash */);

    uint32_t getMinContinuous(void) const { return m_MinContinuous; }


};

} // namespace plugins
} // namespace s2e

#endif /* INPUTENDDETECTOR_H_ */
