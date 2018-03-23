///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SYMBHW_DESCRIPTOR_H
#define S2E_PLUGINS_SYMBHW_DESCRIPTOR_H

#include <string>

#include <s2e/ConfigFile.h>

namespace s2e {
namespace plugins {

class SymbolicHardware;

class DeviceDescriptor {
protected:
    std::string m_id;
    void *m_qemuIrq;
    void *m_qemuDev;
    bool m_active;

    /**
     * Defines whether the device is plugged in at start up.
     * This flag is not affected by hotplug events during execution.
     */
    bool m_pluggedIn;

    struct TypeInfo *m_devInfo;
    struct Property *m_devInfoProperties;
    struct VMStateDescription *m_vmState;
    struct _VMStateField *m_vmStateFields;

public:
    DeviceDescriptor(const std::string &id);

    static DeviceDescriptor *create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key);
    virtual ~DeviceDescriptor();

    struct comparator {
    bool operator()(const DeviceDescriptor *dd1, const DeviceDescriptor *dd2) const {
        return dd1->m_id < dd2->m_id;
    }
    };

    bool isActive() const {
        return m_active;
    }

    bool isPluggedIn() const {
        return m_pluggedIn;
    }

    void setActive(bool b) {
        m_active = true;
    }

    void setDevice(void *qemuDev) {
        m_qemuDev = qemuDev;
    }

    void *getDevice() const {
        return m_qemuDev;
    }

    const std::string &getId() const { return m_id; }

    virtual uint64_t getHostAddress(const struct MemoryRegion *mr) const { return 0; };
    virtual void print(llvm::raw_ostream &os) const {}
    virtual void setInterrupt(bool state) {assert(false);};
    virtual void assignIrq(void *irq) {assert(false);}


    struct VMStateDescription* getVmStateDescription() const { return m_vmState; }
    struct Property* getProperties() const { return m_devInfoProperties; }

    virtual bool isPci() const { return false; }
    virtual bool isIsa() const { return false; }
    virtual bool isConcreteHardware() const { return false; }
};

}
}

#endif
