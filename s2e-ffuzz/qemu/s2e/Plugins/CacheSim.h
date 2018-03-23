///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_CACHESIM_H
#define S2E_PLUGINS_CACHESIM_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>

#include "ModuleExecutionDetector.h"

#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>

#include <klee/Expr.h>

#include <string>
#include <map>
#include <inttypes.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class Cache;
class CacheSimState;

class CacheSim : public Plugin
{
    S2E_PLUGIN
protected:

    struct CacheLogEntry
    {
        uint64_t timestamp;
        uint64_t pc;
        uint64_t address;
        unsigned size;
        bool     isWrite;
        bool     isCode;
        const char* cacheName;
        uint32_t missCount;
    };


    std::vector<CacheLogEntry> m_cacheLog;


    ModuleExecutionDetector *m_execDetector;
    ExecutionTracer *m_Tracer;

    bool m_reportWholeSystem;
    bool m_reportZeroMisses;
    bool m_profileModulesOnly;
    bool m_cacheStructureWrittenToLog;
    bool m_startOnModuleLoad;
    bool m_physAddress;
    sigc::connection m_ModuleConnection;

    sigc::connection m_d1_connection;
    sigc::connection m_i1_connection;

    void onModuleTranslateBlockStart(
        ExecutionSignal* signal,
        S2EExecutionState *state,
        const ModuleDescriptor &desc,
        TranslationBlock *tb, uint64_t pc);


    void onMemoryAccess(S2EExecutionState* state,
                        uint64_t address, unsigned size,
                        bool isWrite, bool isIO, bool isCode);

    void onAfterSymbolicDataMemoryAccess(S2EExecutionState* state,
                        klee::ref<klee::Expr> address,
                        klee::ref<klee::Expr> hostAddress,
                        klee::ref<klee::Expr> value,
                        unsigned flags);

    void onTranslateBlockStart(ExecutionSignal* signal,
                        S2EExecutionState*,
                        TranslationBlock*,
                        uint64_t);

    void onExecuteBlockStart(S2EExecutionState* state, uint64_t pc,
                             TranslationBlock* tb, uint64_t hostAddress);


    void writeCacheDescriptionToLog(S2EExecutionState *state);

    bool profileAccess(S2EExecutionState *state) const;
    bool reportAccess(S2EExecutionState *state) const;
public:
    CacheSim(S2E* s2e): Plugin(s2e) {}
    ~CacheSim();

    void initialize();

    friend class CacheSimState;
};

class CacheSimState: public PluginState
{
private:
    typedef std::map<std::string, Cache*> CachesMap;
    CachesMap m_caches;

    unsigned m_i1_length;
    unsigned m_d1_length;

    Cache* m_i1;
    Cache* m_d1;

public:
    CacheSimState();
    CacheSimState(S2EExecutionState *s, Plugin *p);
    virtual ~CacheSimState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    Cache* getCache(const std::string& name);

    friend class CacheSim;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CACHESIM_H
