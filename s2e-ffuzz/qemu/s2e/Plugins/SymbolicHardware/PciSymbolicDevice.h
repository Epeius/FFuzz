///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SYMBHW_PCI_H
#define S2E_PLUGINS_SYMBHW_PCI_H

#include <vector>

#include <klee/Memory.h>
#include "SymbolicDeviceDescriptor.h"

namespace s2e {
namespace plugins {

class PciDeviceDescriptor:public DeviceDescriptor {
public:
    struct PciResource{
        bool isIo;
        bool is64;
        uint32_t size;
        bool prefetchable;
    };

    typedef std::vector<PciResource> PciResources;

    struct ConcretePciResources {
        unsigned count;
        MemoryRegion regions[PCI_NUM_REGIONS];
        uint32_t flags[PCI_NUM_REGIONS];
    };

    typedef std::vector<ConcretePciResources> PciResourceSchedule;

private:
    uint16_t m_vid;
    uint16_t m_pid;
    uint16_t m_ss_id;
    uint16_t m_ss_vid;
    uint32_t m_classCode;
    uint8_t m_revisionId;
    uint8_t m_interruptPin;
    uint32_t m_capPM;
    uint32_t m_capMSI;
    uint32_t m_capPCIE;
    PciResources m_resources;

    uint32_t m_maxPortSize;
    uint32_t m_maxMmioSize;

    uint32_t m_devfn;
    klee::MemoryObject *m_conf;

    PciResourceSchedule m_schedule;

    PciDeviceDescriptor(const std::string &id);
    virtual void print(llvm::raw_ostream &os) const;

    void initRandomResourceSchedule();
    void initResourceSchedule();

    void onDeviceUpdateMappings(S2EExecutionState *state, void *pci_device,
                                int bar_index, uint64_t old_addr);
    void onDeviceActivation(int bus_type, void *bus);

public:
    virtual ~PciDeviceDescriptor();

    uint16_t getVid() const { return m_vid; }
    uint16_t getPid() const { return m_pid; }
    uint16_t getSsVid() const { return m_ss_vid; }
    uint16_t getSsId() const { return m_ss_id; }
    uint32_t getClassCode() const { return m_classCode; }
    uint8_t getRevisionId() const { return m_revisionId; }
    uint8_t getInterruptPin() const { return m_interruptPin; }

    // Capabilities
    uint32_t getCapPM() const { return m_capPM; }
    uint32_t getCapMSI() const { return m_capMSI; }
    uint32_t getCapPCIE() const { return m_capPCIE; }

    void setDevFn(uint32_t devfn) {
        m_devfn = devfn;
    }

    uint32_t getDevFn() const {
        return m_devfn;
    }

    void initializeSymbolicConfigurationData(S2EExecutionState *state);
    void activateSymbolicConfigurationData(S2EExecutionState *state);


    klee::ref<klee::Expr> readConfig(S2EExecutionState *state, unsigned offset, unsigned size, uint64_t originalValue);

    klee::MemoryObject *getConf() const {
        return m_conf;
    }

    const PciResources& getResources() const { return m_resources; }
    PciResources& getResources() { return m_resources; }
    static PciDeviceDescriptor* create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key);

    virtual void initializeQemuDevice();
    virtual void activateQemuDevice(void *bus);

    virtual void setInterrupt(bool state);
    virtual void assignIrq(void *irq);

    virtual bool readPciAddressSpace(void *buffer, uint32_t offset, uint32_t size);

    virtual bool isPci() const { return true; }
    virtual bool isIsa() const { return false; }

    bool queryResource(S2EExecutionState *state, uint64_t address, klee::ref<klee::Expr> &size);

    const PciResourceSchedule& getSchedule() const { return m_schedule; }
    PciResourceSchedule& getSchedule() { return m_schedule; }
};


}
}
#endif
