///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SYMBHW_VFIO_H
#define S2E_PLUGINS_SYMBHW_VFIO_H

#include <s2e/S2EExecutionState.h>
#include "SymbolicDeviceDescriptor.h"

namespace s2e {
namespace plugins {

class VfioDeviceDescriptor:public DeviceDescriptor {

private:
    void onAddressSpaceChange(
        S2EExecutionState *state,
        const klee::MemoryObject *mo,
        const klee::ObjectState *oldState,
        klee::ObjectState *newState
    );

    void onInitializationComplete(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *oldState, S2EExecutionState *newState);
    void onDeviceUpdateMappings(S2EExecutionState *state, void *pci_device,
                                int bar_index, uint64_t old_addr);

    void initializeSymbolicRegions(S2EExecutionState *state);

    bool m_firstPathSymbolic;
    bool m_symbolicDevice;
    bool m_concreteDeviceActive;

public:
    static VfioDeviceDescriptor* create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key);

    VfioDeviceDescriptor(const std::string &id) : DeviceDescriptor(id) {

    }

    virtual void print(llvm::raw_ostream &os) const;
    virtual void initializeQemuDevice();
    virtual void activateQemuDevice(void *bus);

    virtual void setInterrupt(bool state) { }
    virtual void assignIrq(void *irq) { }

    virtual bool isConcreteHardware() const {
        return m_concreteDeviceActive;
    }
};

}
}

#endif
