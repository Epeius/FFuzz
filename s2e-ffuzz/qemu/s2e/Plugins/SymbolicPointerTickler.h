///
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SymbolicPointerTickler_H
#define S2E_PLUGINS_SymbolicPointerTickler_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/SymbolicHardware/SymbolicHardware.h>

namespace s2e {
namespace plugins {

class SymbolicPointerTickler : public Plugin
{
    S2E_PLUGIN
public:
    SymbolicPointerTickler(S2E* s2e): Plugin(s2e) {}

    void initialize();

private:
    void onSymbolicAddress(S2EExecutionState *state,
                           klee::ref<klee::Expr> virtualAddress,
                           uint64_t concreteAddress,
                           bool &concretize,
                           CorePlugin::symbolicAddressReason reason);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SymbolicPointerTickler_H
