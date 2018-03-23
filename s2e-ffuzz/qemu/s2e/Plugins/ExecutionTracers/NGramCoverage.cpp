///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <iostream>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>

#include "NGramCoverage.h"

namespace s2e {
namespace plugins {

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define MAX_NGRAM           8

class NGramState: public PluginState {
public:
    uint64_t m_countOutputs;
    uint8_t m_map[MAP_SIZE];
    uint64_t m_lastAddr[MAX_NGRAM];
    int m_lastTimerTick;
    static int nGram;

    int hash64(uint64_t val) {
        int v = val & (MAP_SIZE - 1);
        while (val) {
            val >>= MAP_SIZE_POW2;
            v ^= val & (MAP_SIZE - 1);
        }
        return v;
    }

    virtual NGramState* clone() const {
        return new NGramState(*this);
    }

    NGramState() {
        m_countOutputs = 0;
        m_lastTimerTick = 0;
        for (int i = 0; i < MAP_SIZE; i++)
            m_map[i] = 0;
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new NGramState();
    }

    virtual ~NGramState() {

    }

    void addAddr(uint64_t addr) {
        uint64_t addrToHash = 0;
        for (int i = 0; i < nGram - 1; i++) {
            m_lastAddr[i] = m_lastAddr[i+1];
            addrToHash ^= m_lastAddr[i];
            addrToHash <<= 5;
        }
        m_lastAddr[nGram - 1] = addr;
        addrToHash ^= addr;
        if (m_map[hash64(addrToHash)] < 255)
            m_map[hash64(addrToHash)]++;
    }

    void writeToFile(S2E *s2e, S2EExecutionState *state) {
        m_countOutputs++;
        std::ostringstream stringStream;
        stringStream << "NGram-" << state->getID() << "-" << m_countOutputs << ".dat";
        std::string fileName = (std::string)s2e->getOutputFilename(stringStream.str());
        std::ofstream covFile;
        covFile.open(fileName, std::ios::out | std::ios::binary);
        if (covFile.is_open()) {
            covFile.write((char *)m_map, sizeof(m_map));
        }
        covFile.close();
    }
};

int NGramState::nGram = 2;

S2E_DEFINE_PLUGIN(NGramCoverage, "N-gram coverage tracer",
                  "NGramCoverage", "ExecutionTracer", "ModuleExecutionDetector");

void NGramCoverage::initialize()
{
    m_tracer = (ExecutionTracer *)s2e()->getPlugin("ExecutionTracer");
    m_detector = (ModuleExecutionDetector*)
                    s2e()->getPlugin("ModuleExecutionDetector");

    NGramState::nGram = s2e()->getConfig()->getInt(getConfigKey() + ".ngram", 2);
    m_moduleName = s2e()->getConfig()->getString(getConfigKey() + ".moduleName", "");

    m_detector->onModuleTranslateBlockStart.connect(
        sigc::mem_fun(*this, &NGramCoverage::onModuleTranslateBlockStart)
    );

    s2e()->getCorePlugin()->onStateKill.connect(
        sigc::mem_fun(*this, &NGramCoverage::onStateKill)
    );

    s2e()->getCorePlugin()->onTimer.connect_front(
        sigc::mem_fun(*this, &NGramCoverage::onTimer)
    );

}

void NGramCoverage::onModuleTranslateBlockStart(
        ExecutionSignal *signal,
        S2EExecutionState* state,
        const ModuleDescriptor &module,
        TranslationBlock *tb,
        uint64_t pc)
{
    // if a moduleName was configured, trace only inside it
    if (!m_moduleName.empty() && module.Name != m_moduleName)
        return;

    signal->connect(
        sigc::mem_fun(*this, &NGramCoverage::onExecuteBlockStart)
    );
}

void NGramCoverage::onExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
    DECLARE_PLUGINSTATE(NGramState, state);

    const ModuleDescriptor *module = m_detector->getCurrentDescriptor(state);
    if (module)
        plgState->addAddr(pc - module->LoadBase);

    if (plgState->m_lastTimerTick != m_timerTicks) {
        plgState->writeToFile(s2e(), state);
        plgState->m_lastTimerTick = m_timerTicks;
    }
}

void NGramCoverage::onStateKill(S2EExecutionState *state)
{
    DECLARE_PLUGINSTATE(NGramState, state);

    plgState->writeToFile(s2e(), state);
}


} // namespace plugins
} // namespace s2e

