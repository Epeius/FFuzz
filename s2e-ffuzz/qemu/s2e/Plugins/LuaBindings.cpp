///
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>

#include "LuaBindings.h"
#include "LuaModuleDescriptor.h"
#include "LuaAnnotationState.h"
#include "LuaS2EExecutionState.h"
#include "LuaS2EExecutionStateMemory.h"
#include "LuaS2EExecutionStateRegisters.h"
#include "LuaExpression.h"
#include "LuaS2E.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaBindings, "S2E interface for Lua annotations", "LuaBindings",);

void LuaBindings::initialize()
{
    lua_State *L = s2e()->getConfig()->getState();
    Lunar<LuaModuleDescriptor>::Register(L);
    Lunar<LuaS2E>::Register(L);

    m_lua_s2e = new LuaS2E(L);
    Lunar<LuaS2E>::push(L, m_lua_s2e);
    lua_setglobal(L, "g_s2e");

    Lunar<LuaAnnotationState>::Register(L);
    Lunar<LuaS2EExecutionState>::Register(L);
    Lunar<LuaS2EExecutionStateMemory>::Register(L);
    Lunar<LuaS2EExecutionStateRegisters>::Register(L);
    Lunar<LuaExpression>::Register(L);
}

} // namespace plugins
} // namespace s2e
