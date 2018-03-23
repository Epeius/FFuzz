///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "InterruptInjector.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InterruptInjector, "Inject hardware interrupts at various places in the system to cause race conditions",
                  "InterruptInjector",
                  "SymbolicHardware", "LibraryCallMonitor");

void InterruptInjector::initialize()
{
    m_libcallMonitor = static_cast<LibraryCallMonitor*>(s2e()->getPlugin("LibraryCallMonitor"));
    m_symbolicHardware = static_cast<SymbolicHardware*>(s2e()->getPlugin("SymbolicHardware"));

    m_libcallMonitor->onLibraryCall.connect(
            sigc::mem_fun(*this, &InterruptInjector::onLibraryCall));

    m_hardwareId = s2e()->getConfig()->getString(getConfigKey() + ".hardwareId");

    m_deviceDescriptor = m_symbolicHardware->findDevice(m_hardwareId);
    if (!m_deviceDescriptor) {
        getWarningsStream() << "InterruptInjector: you must specifiy a valid hardware id.\n";
        exit(-1);
    }
}

void InterruptInjector::onLibraryCall(S2EExecutionState* state,
                                      FunctionMonitorState* fns,
                                      const ModuleDescriptor& mod)
{
    m_deviceDescriptor->setInterrupt(true);
}

} // namespace plugins
} // namespace s2e
