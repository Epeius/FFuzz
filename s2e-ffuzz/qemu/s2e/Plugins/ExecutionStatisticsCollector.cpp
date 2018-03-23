///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "ExecutionStatisticsCollector.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExecutionStatisticsCollector, "Allows client plugins to store statistics in a central location",
                  "ExecutionStatisticsCollector");

void ExecutionStatisticsCollector::initialize()
{
    m_detector = static_cast<ModuleExecutionDetector*>(s2e()->getPlugin("ModuleExecutionDetector"));
}

} // namespace plugins
} // namespace s2e
