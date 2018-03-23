///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_ConsistencyModels_H
#define S2E_PLUGINS_ConsistencyModels_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <stack>

namespace s2e {
namespace plugins {

enum ExecutionConsistencyModel {
    NONE, OVERCONSTR, STRICT, LOCAL, OVERAPPROX
};


class ConsistencyModelsState:public PluginState
{
private:
    ExecutionConsistencyModel m_defaultModel;
    std::stack<ExecutionConsistencyModel> m_models;
public:

    ConsistencyModelsState(ExecutionConsistencyModel model) {
        m_defaultModel = model;
    }

    virtual ~ConsistencyModelsState() {}

    virtual ConsistencyModelsState* clone() const {
        return new ConsistencyModelsState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    ExecutionConsistencyModel get() const {
        if (m_models.size() == 0) {
            return m_defaultModel;
        }
        return m_models.top();
    }

    void push(ExecutionConsistencyModel model) {
        m_models.push(model);
    }

    ExecutionConsistencyModel pop() {
        if (m_models.size() == 0) {
            return m_defaultModel;
        }
        ExecutionConsistencyModel model = m_models.top();
        m_models.pop();
        return model;
    }

};


class ConsistencyModels : public Plugin
{
    S2E_PLUGIN
public:
    ConsistencyModels(S2E* s2e): Plugin(s2e) {}

    void initialize();

    static ExecutionConsistencyModel fromString(const std::string &model);
    ExecutionConsistencyModel getDefaultModel() const {
        return m_defaultModel;
    }

    void push(S2EExecutionState *state, ExecutionConsistencyModel model) {
        DECLARE_PLUGINSTATE(ConsistencyModelsState, state);
        plgState->push(model);
    }

    ExecutionConsistencyModel pop(S2EExecutionState *state) {
        DECLARE_PLUGINSTATE(ConsistencyModelsState, state);
        return plgState->pop();
    }

    ExecutionConsistencyModel get(S2EExecutionState *state) {
        DECLARE_PLUGINSTATE(ConsistencyModelsState, state);
        return plgState->get();
    }

private:
    ExecutionConsistencyModel m_defaultModel;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ConsistencyModels_H
