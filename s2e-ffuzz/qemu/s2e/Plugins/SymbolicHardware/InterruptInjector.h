///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_INTERRUPT_INJECTOR_H
#define S2E_PLUGINS_INTERRUPT_INJECTOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/LibraryCallMonitor.h>
#include "SymbolicHardware.h"

namespace s2e {
namespace plugins {

class InterruptInjector : public Plugin
{
    S2E_PLUGIN
public:
    InterruptInjector(S2E* s2e): Plugin(s2e) {}

    void initialize();


private:
    LibraryCallMonitor *m_libcallMonitor;
    SymbolicHardware *m_symbolicHardware;

    std::string m_hardwareId;
    DeviceDescriptor *m_deviceDescriptor;

    void onLibraryCall(S2EExecutionState* state,
                       FunctionMonitorState* fns,
                       const ModuleDescriptor& mod);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_INTERRUPT_INJECTOR_H
