///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_Screenshot_H
#define S2E_PLUGINS_Screenshot_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <string>

namespace s2e {
namespace plugins {

class Screenshot : public Plugin
{
    S2E_PLUGIN
public:
    Screenshot(S2E* s2e): Plugin(s2e) {}

    void initialize();
    void takeScreenShot(const std::string &fileName);
    std::string takeScreenShot(S2EExecutionState *state);

private:
    unsigned m_period;
    unsigned m_counter;

    void onTimer();

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_Screenshot_H
