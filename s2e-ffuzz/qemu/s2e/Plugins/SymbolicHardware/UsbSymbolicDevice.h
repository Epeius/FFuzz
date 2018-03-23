///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SYMBHW_USB_H
#define S2E_PLUGINS_SYMBHW_USB_H

#include <s2e/S2EExecutionState.h>
#include "SymbolicDeviceDescriptor.h"

namespace s2e {
namespace plugins {

class UsbDeviceDescriptor:public DeviceDescriptor {

private:
    void onInitializationComplete(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *oldState, S2EExecutionState *newState);

    bool m_concreteDeviceActive;

public:
    static UsbDeviceDescriptor* create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key);

    UsbDeviceDescriptor(const std::string &id) : DeviceDescriptor(id) {

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
