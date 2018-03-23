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

#ifndef TESTCASEFILTER_H_
#define TESTCASEFILTER_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/Plugins/Linux/LinuxMonitor2.h>

#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>

#include <algorithm>
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

#include "InputEndDetector.h"

using namespace llvm::sys;

namespace s2e {
namespace plugins{

class SizePathConstraint
{
private:
    uint64_t size;
    std::set< klee::ref<klee::Expr> > pc;
public:
    SizePathConstraint(uint64_t size, std::set< klee::ref<klee::Expr> > pc) : size(size), pc(pc) {};
    inline uint64_t getPathSize(void) const {return size;}
    std::set< klee::ref<klee::Expr> > & getPathConstrait(void) {return pc;}
};


class LoopBucket
{
public:
    uint64_t pc;
    bool     buckets[11]; // 0, 1, 2, 3-4, 5-8, 9-16, 17-32, 33-64, 65-128, 129-256, 257-max.
public:
    LoopBucket(uint64_t _pc): pc(_pc) {
        std::fill_n(buckets, 11, false);
    }
};

//TODO: Shrink so many data structures.

/*
 * TestcaseFilter: Filtering redundant test-cases ASAP using expression evaluation.
 */
class TestcaseFilter : public Plugin
{
public:

	S2E_PLUGIN


#define SYMNAME		"sym_target_file"
#define OFFSDIR     "/tmp/afl_offsets"

private:
    // type definition
    typedef std::set< klee::ref<klee::Expr> > PathConstraint; // use path constraint to represent a path

    struct SortBySymSize
    {
        bool operator ()(const SizePathConstraint* _s1,
                const SizePathConstraint* _s2) const
        {
            return _s1->getPathSize() <= _s2->getPathSize();
        }
    };

    typedef std::set< SizePathConstraint*, SortBySymSize >TouchedPaths;
    typedef std::map <uint64_t, PathConstraint > ID_PC;
    typedef std::map <uint64_t, std::set<uint64_t> > ID_ConHash;
    typedef std::map <uint64_t, uint32_t> ID_HotDegree;
    typedef std::map <uint64_t, S2EExecutionState*> ID_State;
    typedef std::map <uint32_t, std::set<S2EExecutionState* > > InputSize_States;

    // members
    TouchedPaths m_touched_symSize_PC;// collection of all touched paths

    InputSize_States    m_input_states;
    ID_ConHash          m_sigID_ConHash;
    ID_PC               m_sigID_ConInMainImage; // only collect the constraint in main image
    std::map <uint32_t, std::set<uint64_t> > m_drill_ConHash;
    std::map <uint32_t, std::set<LoopBucket*> > m_dril_inputsizeLB;

    ID_State            m_sigID_States;

    ID_HotDegree        m_sigID_HD;
    uint32_t            m_sampleFreq; // interval of computing hot degree increment (testcase number, not time)
    uint32_t            m_FreqCounter;

    /* Offsets that related with symbolic branches, collect these offsets for AFL */
    std::set<uint32_t> m_sigOffset;

    bool m_collectOffs;
    uint32_t m_hottestNum;

    bool m_ModeSwitched;

    InputEndDetector* m_IED;

    uint64_t m_mainImageBase;
    uint64_t m_mainImageEnd;


private:

    void CollectSignificantOffs(S2EExecutionState *state);

    void findInputBytes(klee::ref<klee::Expr>, std::set<uint32_t>&);

    void addTouchedPath(int size, PathConstraint pc) {
        SizePathConstraint* addpc = new SizePathConstraint(size, pc);
        m_touched_symSize_PC.insert(addpc);
    }

    bool updateHotStates(void);

    bool filterSplitedStateFast(S2EExecutionState*,
                                    std::set<uint64_t>&,
                                    std::set<uint64_t>&,
                                    bool&);

    void onDisabledFork(S2EExecutionState* originalState, klee::ref<klee::Expr> & Condition);

public:
    TestcaseFilter(S2E* s2e) : Plugin(s2e) { };

    void initialize();

    bool addSigState(S2EExecutionState* state);

    ID_State& getSigStates(void) {
        return m_sigID_States;
    }



    void displayHD(void);
    inline bool getModeSwitched() {return m_ModeSwitched;}
    inline void setModeSwitched(bool _switched) {m_ModeSwitched = _switched;}

    inline uint32_t getMAXstates(void) {return m_hottestNum;}

    /* Kill last states that added into sigStates because fuzzer told us it didn't touch any new path */
    void simpSigStates(uint64_t);

    bool isRedundant(const char* filename, bool*);

    /* When drilling, check whether this branch has been touched before */
    bool checkRedundantFast(S2EExecutionState*, uint64_t hitcount);

    inline bool checkLoopBucketFast(S2EExecutionState* _state, uint64_t hitcount);

    void cleanup(uint64_t);

    void setMainImage(uint64_t base, uint64_t size) {
        m_mainImageBase = base;
        m_mainImageEnd = base + size;
    }

    inline bool isMainImage(uint64_t pc) {
        return pc >= m_mainImageBase && pc <= m_mainImageEnd;
    }

    ~TestcaseFilter();
};

} // namespace plugins
} // namespace s2e

#endif /* TESTCASEFILTER_H_ */
