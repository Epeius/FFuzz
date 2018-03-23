///
/// Copyright (C) 2014, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_LUABINDINGS_H
#define S2E_PLUGINS_LUABINDINGS_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include "LuaS2E.h"

namespace s2e {
namespace plugins {

/**
 *  This plugin acts as a centralized registry for all Lua bindings.
 */
class LuaBindings : public Plugin
{
    S2E_PLUGIN

    LuaS2E *m_lua_s2e;
public:
    LuaBindings(S2E* s2e): Plugin(s2e) {}

    void initialize();
};

} // namespace plugins
} // namespace s2e

#endif
