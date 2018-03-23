///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


extern "C" {
void vga_hw_screen_dump(const char *filename);
#include <qstring.h>
}

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include "QEMUEvents.h"
#include "Screenshot.h"

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Screenshot, "Screenshot S2E plugin", "",);

void Screenshot::initialize()
{
    m_period = s2e()->getConfig()->getInt(getConfigKey() + ".period", 5);
    m_counter = 0;


    s2e()->getCorePlugin()->onTimer.connect(
            sigc::mem_fun(*this, &Screenshot::onTimer));
}

void Screenshot::takeScreenShot(const std::string &fileName)
{
    vga_hw_screen_dump(fileName.c_str());
}

std::string Screenshot::takeScreenShot(S2EExecutionState *state)
{
    std::stringstream filename;
    filename << "screenshot" << state->getID() << ".png";
    std::string outputFile = s2e()->getOutputFilename(filename.str());
    takeScreenShot(outputFile);

    return filename.str();
}

void Screenshot::onTimer()
{
    if (!g_s2e_state) {
        return;
    }

    if ((m_counter % m_period) == 0) {
        std::string outputFile = takeScreenShot(g_s2e_state);
        if (monitor_ready()) {
            QEMUEvents::PluginData data;
            QString *str = qstring_from_str(outputFile.c_str());
            data.push_back(std::make_pair("filename", QOBJECT(str)));
            QEMUEvents::emitQMPEvent(this, data);
        }
    }

    ++m_counter;
}

} // namespace plugins
} // namespace s2e
