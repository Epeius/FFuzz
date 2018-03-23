///
/// Copyright (C) 2012-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "ConsistencyModels.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ConsistencyModels, "Central manager for execution consistency models", "",);

void ConsistencyModels::initialize()
{
    ConfigFile *cfg = s2e()->getConfig();
    bool ok = false;

    std::string consistency = cfg->getString(getConfigKey() + ".model", "", &ok);
    m_defaultModel = fromString(consistency);

    if (m_defaultModel == NONE) {
        getWarningsStream() << "ConsistencyModels: invalid consistency " << consistency << "\n";
        exit(-1);
    }
}

ExecutionConsistencyModel ConsistencyModels::fromString(const std::string &model)
{
    ExecutionConsistencyModel ret = NONE;
    //Check the consistency type
    if (model == "strict") {
        ret = STRICT;
    }else if (model == "local") {
        ret = LOCAL;
    }else if (model == "overapproximate") {
        ret = OVERAPPROX;
    }else if  (model == "overconstrained") {
        ret = OVERCONSTR;
    }

    return ret;
}

PluginState *ConsistencyModelsState::factory(Plugin *p, S2EExecutionState *s) {
    ConsistencyModels *models = static_cast<ConsistencyModels*>(p);
    return new ConsistencyModelsState(models->getDefaultModel());
}


} // namespace plugins
} // namespace s2e
