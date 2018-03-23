///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/cpu.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Vmi.h>

#include <vmi/FileProvider.h>
#include <vmi/RegisterProvider.h>
#include <vmi/WindowsCrashDumpGenerator.h>

#include <llvm/Support/Path.h>
#include <llvm/Support/FileSystem.h>

#include <iostream>
#include <sstream>

#include "WindowsCrashDumpGenerator.h"
#include "BlueScreenInterceptor.h"

namespace s2e {
namespace plugins {

using namespace vmi::windows;

S2E_DEFINE_PLUGIN(WindowsCrashDumpGenerator, "Generates WinDbg-compatible crash dumps",
                  "WindowsCrashDumpGenerator", "Interceptor");

void WindowsCrashDumpGenerator::initialize()
{
    //Register the LUA API for crash dump generation
    Lunar<WindowsCrashDumpInvoker>::Register(s2e()->getConfig()->getState());

    m_monitor = dynamic_cast<WindowsInterceptor*>(s2e()->getPlugin("Interceptor"));
    m_generateCrashDump = s2e()->getConfig()->getBool(getConfigKey() + ".generateCrashDump", false);

    if (m_generateCrashDump) {
        BlueScreenInterceptor *bsod = dynamic_cast<BlueScreenInterceptor*>(s2e()->getPlugin("BlueScreenInterceptor"));
        if (!bsod) {
            getWarningsStream() << "WindowsCrashDumpGenerator: BlueScreenInterceptor needs to be activated\n";
            exit(-1);
        }

        bsod->onBlueScreen.connect(
            sigc::mem_fun(*this, &WindowsCrashDumpGenerator::onBlueScreen)
        );
    }
}

void WindowsCrashDumpGenerator::onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info)
{
    generateDump(state, getPathForDump(state), info);
}

bool WindowsCrashDumpGenerator::generateManualDump(S2EExecutionState *state,
                                                   const std::string &filename,
                                                   const BugCheckDescription *info)
{
    BugCheckDescription newInfo = *info;
    newInfo.code = 0xDEADDEAD; //MANUALLY_INITIATED_CRASH1

    CONTEXT32 context;
    m_monitor->getContext32(state, context);
    context.Eip = state->getPc();

    return generateCrashDump(state, filename, &newInfo, context);

}

bool WindowsCrashDumpGenerator::generateDump(S2EExecutionState *state, const std::string &filename,
                                             const BugCheckDescription *info)
{
    CONTEXT32 context;
    m_monitor->getContext32(state, context);

    return generateCrashDump(state, filename, info, context);
}

bool WindowsCrashDumpGenerator::generateCrashDump(S2EExecutionState *state,
                                                  const std::string &filename,
                                                  const BugCheckDescription *bugDesc,
                                                  const CONTEXT32 &context)
{
    getDebugStream(state)
        << "WindowsCrashDumpGenerator: generating dump in "
        << filename << "\n";

    vmi::FileSystemFileProvider fp(filename);
    if (!fp.open(true)) {
        getWarningsStream(state)
                << "WindowsCrashDumpGenerator: could not open "
                << filename << " for writing - "
                << strerror(errno) << "\n";
        return false;
    }

    vmi::GuestMemoryFileProvider physicalMemory(state, &Vmi::readGuestPhysical, NULL, filename);
    vmi::GuestMemoryFileProvider virtualMemory(state, &Vmi::readGuestVirtual, &Vmi::writeGuestVirtual, filename);

    vmi::X86RegisterProvider registers(state, &Vmi::readX86Register, NULL);


    vmi::windows::WindowsCrashDumpGenerator crashGen(&virtualMemory,
                                            &physicalMemory,
                                            &registers,
                                            &fp);

    bool retd = false;

    if (bugDesc->guestHeader) {
        if (state->getPointerSize() == 4) {
            CONTEXT32 context;
            m_monitor->getContext32(state, context);
            retd = crashGen.generate(*bugDesc, &context, sizeof(context));
        } else {
            CONTEXT64 context;
            m_monitor->getContext64(state, context);
            retd = crashGen.generate(*bugDesc, &context, sizeof(context));
        }
    } else {
         retd = crashGen.generate(
                    m_monitor->getKdDebuggerDataBlock(),
                    m_monitor->getKprcbAddress(),
                    m_monitor->getVersionBlock(),
                    context,
                    *bugDesc
                );
    }

    if (!retd) {
        getDebugStream(state)
            << "WindowsCrashDumpGenerator: could not generated dump\n";
        return false;
    }

    uint64_t size;
    std::error_code error = llvm::sys::fs::file_size(filename, size);
    if (error) {
        getWarningsStream(state) << "WindowsCrashDumpGenerator: Unable to determine size of "
                                 << filename << " - " << error.message() << '\n';
        return false;
    } else {
        getDebugStream(state)
            << "WindowsCrashDumpGenerator: dump size " << hexval(size) << "\n";
    }

    return true;
}

const char WindowsCrashDumpInvoker::className[] = "WindowsCrashDumpInvoker";

Lunar<WindowsCrashDumpInvoker>::RegType WindowsCrashDumpInvoker::methods[] = {
  LUNAR_DECLARE_METHOD(WindowsCrashDumpInvoker, generateCrashDump),
  {0,0}
};


WindowsCrashDumpInvoker::WindowsCrashDumpInvoker(WindowsCrashDumpGenerator *plg)
{
    m_plugin = plg;
}

WindowsCrashDumpInvoker::WindowsCrashDumpInvoker(lua_State *lua)
{
    m_plugin = static_cast<WindowsCrashDumpGenerator*>(g_s2e->getPlugin("WindowsCrashDumpGenerator"));
}

WindowsCrashDumpInvoker::~WindowsCrashDumpInvoker()
{

}

int WindowsCrashDumpInvoker::generateCrashDump(lua_State *L)
{
    llvm::raw_ostream &os = g_s2e->getDebugStream();

    if (!lua_isstring(L, 1)) {
        os << "First argument to " << __FUNCTION__ << " must be the prefix of the crash dump" << '\n';
        return 0;
    }

    std::string prefix = luaL_checkstring(L, 1);

    S2EExecutionState *state = g_s2e_state;
    int stateId = g_s2e_state->getID();
    if (lua_isnumber(L, 2)) {
        stateId = lua_tointeger(L, 2);
        state = NULL;

        //Fetch the right state
        //XXX: Avoid linear search
        const klee::StateSet &states = g_s2e->getExecutor()->getStates();
        foreach2(it, states.begin(), states.end()) {
            S2EExecutionState *ss = static_cast<S2EExecutionState*>(*it);
            if (ss->getID() == stateId) {
                state = ss;
                break;
            }
        }
    }

    if (state == NULL) {
        os << "State with id " << stateId << " does not exist" << '\n';
        return 0;
    }

    if (!m_plugin) {
        os << "Please enable the WindowsCrashDumpGenerator plugin in your configuration file" << '\n';
        return 0;
    }

    std::string path = m_plugin->getPathForDump(state);

    BugCheckDescription desc;
    m_plugin->generateManualDump(state, path, &desc);

    return 0;
}

std::string WindowsCrashDumpGenerator::getPathForDump(S2EExecutionState *state, const std::string &prefix)
{
    std::stringstream filename;
    filename << prefix << state->getID() << ".dmp";

    return g_s2e->getOutputFilename(filename.str());
}


} // namespace plugins
} // namespace s2e
