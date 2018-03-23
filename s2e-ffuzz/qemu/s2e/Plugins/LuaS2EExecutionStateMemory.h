///
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef _LUA_S2E_EXECUTION_STATE_MEMORY_

#define _LUA_S2E_EXECUTION_STATE_MEMORY_

#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/Lua.h>

namespace s2e {
namespace plugins {

class LuaS2EExecutionStateMemory {
private:
    S2EExecutionState *m_state;
public:
    static const char className[];
    static Lunar<LuaS2EExecutionStateMemory>::RegType methods[];

    LuaS2EExecutionStateMemory(lua_State *lua) {
        m_state = NULL;
    }

    LuaS2EExecutionStateMemory(S2EExecutionState *state) {
        m_state = state;
    }

    int readPointer(lua_State *L);
    int write(lua_State *L);
};

}
}

#endif
