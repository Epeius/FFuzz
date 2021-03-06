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
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef S2ETOOLS_DEBUGGER_H
#define S2ETOOLS_DEBUGGER_H

#include "lib/BinaryReaders/Library.h"

namespace s2etools
{

class ExecutionDebugger
{
private:
    std::ostream &m_os;

    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;


    void onItem(unsigned traceIndex,
                const s2e::plugins::ExecutionTraceItemHeader &hdr,
                void *item);

public:
    ExecutionDebugger(Library *lib, ModuleCache *cache, LogEvents *events, std::ostream &os);
    ~ExecutionDebugger();

};

class MemoryDebugger : public LogEvents
{
private:

    enum Type {
        UNDEFINED,
        LOOK_FOR_VALUE
    };

    std::ostream &m_os;

    LogEvents *m_events;
    ModuleCache *m_cache;
    Library *m_library;

    sigc::connection m_connection;

    Type m_analysisType;

    uint64_t m_valueToFind;

    void onItem(unsigned traceIndex,
                const s2e::plugins::ExecutionTraceItemHeader &hdr,
                void *item);


    void printHeader(const s2e::plugins::ExecutionTraceItemHeader &hdr);
    void doLookForValue(const s2e::plugins::ExecutionTraceItemHeader &hdr,
                                        const s2e::plugins::ExecutionTraceMemory &item);

    void doPageFault(const s2e::plugins::ExecutionTraceItemHeader &hdr,
                                     const s2e::plugins::ExecutionTracePageFault &item);

public:

    MemoryDebugger(Library *lib, ModuleCache *cache, LogEvents *events, std::ostream &os);
    ~MemoryDebugger();

    void lookForValue(uint64_t value) {
        m_analysisType = LOOK_FOR_VALUE;
        m_valueToFind = value;
    }

};


/**
 *  This is a collection of functions to analyze the execution traces
 *  for the purpose of debugging S2E.
 */
class Debugger
{
private:
    std::string m_fileName;
    LogParser m_parser;

    ModuleCache *m_ModuleCache;
    Library m_binaries;

    void processCallItem(unsigned traceIndex,
                         const s2e::plugins::ExecutionTraceItemHeader &hdr,
                         const s2e::plugins::ExecutionTraceCall &call);




public:
    Debugger(const std::string &file);
    ~Debugger();

    void process();
};

}

#endif
