///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "StackChecker.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <sstream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StackChecker, "Verfies the correct stack use", "", "MemoryChecker", "StackMonitor");

void StackChecker::initialize()
{
    m_stackMonitor = static_cast<StackMonitor*>(s2e()->getPlugin("StackMonitor"));
    m_memoryChecker = static_cast<MemoryChecker*>(s2e()->getPlugin("MemoryChecker"));
    m_monitor = static_cast<OSMonitor*>(s2e()->getPlugin("Interceptor"));

    m_memoryChecker->onPostCheck.connect(
        sigc::mem_fun(*this, &StackChecker::onMemoryAccess));
}

void StackChecker::onMemoryAccess(S2EExecutionState *state, uint64_t address,
                                  unsigned size, bool isWrite, bool *result)
{
    //XXX: This is a hack until we grant param rights for each entry point.
    uint64_t stackBase = 0, stackSize = 0;
    m_monitor->getCurrentStack(state, &stackBase, &stackSize);
    if (address >= stackBase && (address < stackBase + stackSize)) {
        *result = true;
        return;
    }


    StackFrameInfo info;
    bool onTheStack = false;
    bool res = m_stackMonitor->getFrameInfo(state, address, onTheStack, info);

    *result = false;

    if (!onTheStack) {
        m_stackMonitor->dump(state);
        return;
    }

    //We are not accessing any valid frame
    if (!res) {
        std::stringstream err;

        err << "StackChecker: "
                << "BUG: memory range at " << hexval(address) << " of size " << hexval(size)
                << " is a stack location but cannot be accessed by instruction " << m_memoryChecker->getPrettyCodeLocation(state)
                << ": invalid frame!" << std::endl;

        if (m_memoryChecker->terminateOnErrors()) {
            s2e()->getExecutor()->terminateStateEarly(*state, err.str());
        }
    }

    *result = true;
}

} // namespace plugins
} // namespace s2e
