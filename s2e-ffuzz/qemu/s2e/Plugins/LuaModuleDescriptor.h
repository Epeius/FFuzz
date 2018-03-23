///
/// Copyright (C) 2014-2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef _LUA_MODULE_DESCRIPTOR_

#define _LUA_MODULE_DESCRIPTOR_

#include <s2e/Plugins/ModuleDescriptor.h>
#include <s2e/Plugins/Lua.h>

namespace s2e {
namespace plugins {

class LuaModuleDescriptor {
private:
    ModuleDescriptor m_desc;
public:
    static const char className[];
    static Lunar<LuaModuleDescriptor>::RegType methods[];

    LuaModuleDescriptor(lua_State *lua) {

    }

    LuaModuleDescriptor(const ModuleDescriptor &desc) {
        m_desc = desc;
    }

    int getPid(lua_State *L);
    int getName(lua_State *L);
    int getNativeBase(lua_State *L);
    int getLoadBase(lua_State *L);
    int getSize(lua_State *L);
    int getEntryPoint(lua_State *L);
};

}
}

#endif
