///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include "CodePatternFinder.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CodePatternFinder, "Sends a notification when a given code pattern is about to be executed", "",);

void CodePatternFinder::initialize()
{
    m_map = s2e()->getPlugin<ModuleMap>();
    if (!m_map) {
        getWarningsStream() << "ModuleMap plugin is missing, won't have any module info\n";
    }

    ConfigFile *cfg = s2e()->getConfig();

    m_codePatternSize = cfg->getListSize(getConfigKey() + ".pattern");
    ConfigFile::integer_list pattern = cfg->getIntegerList(getConfigKey() + ".pattern");

    if (m_codePatternSize == 0) {
        getDebugStream() << "binary pattern is empty\n";
        exit(-1);
    }

    if (m_codePatternSize > MAX_PATTERN_SIZE) {
        getDebugStream() << "binary pattern is larger than " << MAX_PATTERN_SIZE << "\n";
        exit(-1);
    }

    for (unsigned i = 0; i < m_codePatternSize; ++i) {
        if (pattern[i] > 255) {
            getDebugStream() << "binary pattern contains value > 255\n";
            exit(-1);
        }

        m_codePattern[i] = pattern[i];
    }



    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &CodePatternFinder::onTranslateBlockStart));
}

void CodePatternFinder::onTranslateBlockStart(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
    uint8_t buffer[MAX_PATTERN_SIZE];

    if (!state->readMemoryConcrete(pc, buffer, m_codePatternSize)) {
        return;
    }

    if (!memcmp(buffer, m_codePattern, m_codePatternSize)) {
        std::stringstream ss;
        const ModuleDescriptor *desc;
        if (m_map && (desc = m_map->getModule(state, pc))) {
            ss << desc->Name << ":" << std::hex << desc->ToNativeBase(pc);
        } else {
            ss << std::hex << pc;
        }

        getWarningsStream(state) << "Code pattern found at " << ss.str() << "\n";
    }
}


} // namespace plugins
} // namespace s2e
