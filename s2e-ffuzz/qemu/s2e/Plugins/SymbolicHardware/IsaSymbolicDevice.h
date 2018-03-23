///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SYMBHW_ISA_H
#define S2E_PLUGINS_SYMBHW_ISA_H

#include <s2e/ConfigFile.h>

#include "SymbolicDeviceDescriptor.h"

namespace s2e {
namespace plugins {

class IsaDeviceDescriptor:public DeviceDescriptor {
public:
    struct IsaResource {
        uint16_t portBase;
        uint16_t portSize;
        uint8_t irq;
    };

private:
    IsaResource m_isaResource;

    struct TypeInfo *m_isaInfo;
    struct Property *m_isaProperties;
    struct VMStateDescription *m_vmState;
    struct _VMStateField *m_vmStateFields;

    void onDeviceActivation(int bus_type, void *bus);

public:
    IsaDeviceDescriptor(const std::string &id, const IsaResource &res);

    static IsaDeviceDescriptor* create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key);
    virtual ~IsaDeviceDescriptor();
    virtual void print(llvm::raw_ostream &os) const;
    virtual void initializeQemuDevice();
    virtual void activateQemuDevice(void *bus);

    const IsaResource& getResource() const {
        return m_isaResource;
    }

    virtual void setInterrupt(bool state);
    virtual void assignIrq(void *irq);

    virtual bool isPci() const { return false; }
    virtual bool isIsa() const { return true; }
};

}
}

#endif
