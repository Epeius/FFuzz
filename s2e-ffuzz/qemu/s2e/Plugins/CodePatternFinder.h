///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_CodePatternFinder_H
#define S2E_PLUGINS_CodePatternFinder_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/ModuleMap.h>

#include <vector>

namespace s2e {
namespace plugins {

class CodePatternFinder : public Plugin
{
    S2E_PLUGIN
public:
    CodePatternFinder(S2E* s2e): Plugin(s2e) {}

    void initialize();


    static const unsigned MAX_PATTERN_SIZE = 256;

private:
    ModuleMap *m_map;

    uint8_t m_codePattern[MAX_PATTERN_SIZE];
    unsigned m_codePatternSize;

    void onTranslateBlockStart(ExecutionSignal *signal,
                               S2EExecutionState *state,
                               TranslationBlock *tb,
                               uint64_t pc);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CodePatternFinder_H
