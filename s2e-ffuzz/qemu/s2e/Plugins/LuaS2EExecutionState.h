///
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef _LUA_S2E_EXECUTION_STATE_

#define _LUA_S2E_EXECUTION_STATE_

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/Lua.h>
#include "LuaS2EExecutionStateMemory.h"
#include "LuaS2EExecutionStateRegisters.h"


namespace s2e {
namespace plugins {

class LuaS2EExecutionState {
private:
    S2EExecutionState *m_state;
    LuaS2EExecutionStateMemory m_memory;
    LuaS2EExecutionStateRegisters m_registers;
public:
    static const char className[];
    static Lunar<LuaS2EExecutionState>::RegType methods[];

    LuaS2EExecutionState(lua_State *lua) : m_memory((S2EExecutionState *)NULL), m_registers((S2EExecutionState *)NULL) {
        m_state = NULL;
    }

    LuaS2EExecutionState(S2EExecutionState *state) : m_memory(state), m_registers(state) {
        m_state = state;
    }

    int mem(lua_State *L);
    int regs(lua_State *L);
    int createSymbolicValue(lua_State *L);
    int kill(lua_State *L);
    int setPluginProperty(lua_State *L);
    int getPluginProperty(lua_State *L);
    int debug(lua_State *L);
};

}
}

#endif
