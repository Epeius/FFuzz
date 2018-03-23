///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_PLUGINS_SYMBHW_H
#define S2E_PLUGINS_SYMBHW_H

extern "C" {
#include "hw/pci.h"
}

#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/BaseInstructions.h>

#include <llvm/ADT/BitVector.h>
#include <llvm/ADT/DenseSet.h>

#include <string>
#include <set>
#include <map>

#include "SymbolicDeviceDescriptor.h"

namespace s2e {
namespace plugins {

enum S2E_SYMBHW_COMMANDS {
    SYMBHW_PLUG_IN,
    SYMBHW_HAS_PCI,
    SYMBHW_UNPLUG,
    SYMBHW_REGISTER_DMA_MEMORY,
    SYMBHW_UNREGISTER_DMA_MEMORY,
    SYMBHW_INJECT_INTERRUPT,
    SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS,
    SYMBHW_QUERY_RESOURCE_SIZE,
    SYMBHW_SELECT_NEXT_PCI_CONFIG,
    SYMBHW_DEACTIVATE_SYMBOLIC_PCI_BUS,
    SYMBHW_GET_CURRENT_PCI_CONFIG,
}  __attribute__((aligned(8)));

struct S2E_SYMHW_DMA_MEMORY {
    uint64_t PhysicalAddress;
    uint64_t Size;
}  __attribute__((aligned(8)));;

struct S2E_SYMHW_RESOURCE {
    /* Input to identify the resource */
    uint64_t PhysicalAddress;

    /* Output is a constrained symbolic size */
    uint64_t Size;
}  __attribute__((aligned(8)));;

struct S2E_SYMBHW_COMMAND {
    S2E_SYMBHW_COMMANDS Command;
    union {
        S2E_SYMHW_DMA_MEMORY Memory;
        S2E_SYMHW_RESOURCE Resource;
        uint64_t HasPci;
        uint64_t InterruptLevel;
        uint64_t SelectNextConfigSuccess;
        uint64_t DeviceIndex;
        uint64_t CurrentConfig;
    };
}  __attribute__((aligned(8)));;

class PciDeviceDescriptor;

class SymbolicHardware : public Plugin, public BaseInstructionsPluginInvokerInterface
{
    S2E_PLUGIN
public:

    typedef std::set<DeviceDescriptor *,DeviceDescriptor::comparator > DeviceDescriptors;
    typedef llvm::DenseSet<MemoryRegion*> SymbolicMemoryRegions;

public:
    SymbolicHardware(S2E* s2e): Plugin(s2e) {}
    virtual ~SymbolicHardware();
    void initialize();

    DeviceDescriptor *findDevice(const std::string &name) const;

    void setSymbolicPortRange(uint16_t start, unsigned size, bool isSymbolic);
    bool isSymbolic(uint16_t port) const;

    bool isMmioSymbolic(struct MemoryRegion *mr, uint64_t physaddress, uint64_t size) const;
    bool setSymbolicMmioRange(S2EExecutionState *state, uint64_t physaddr, uint64_t size);
    void setSymbolicMmioRange(struct MemoryRegion *mr);
    bool resetSymbolicMmioRange(S2EExecutionState *state, uint64_t physaddr, uint64_t size);
    void resetSymbolicMmioRange(struct MemoryRegion *mr);
    void registerMemoryListeners();

    bool isDerivedFromDmaMemory(S2EExecutionState *state, const klee::ref<klee::Expr> &address,
                                llvm::SmallVector<std::pair<const klee::Array*, uint64_t>, 2> &physicalAddresses);

    klee::ref<klee::Expr> createExpression(S2EExecutionState *state, SymbolicHardwareAccessType type, uint64_t address, unsigned size,
                                           const std::vector<uint8_t> &concolicValue);

    PciDeviceDescriptor *getPciDevice(uint32_t cmd) const;

    void setDmaHook(SymbolicMemoryHook &hook) {
        m_dmaHook = hook;
    }

    SymbolicMemoryHook &getDmaHook() {
        return m_dmaHook;
    }

    bool isRunningConcreteHardware() const;

    /**
     * Clients register to this event to control whether
     * a symbolic value should be created upon a read from a symbolic
     * hardware region.
     */
    sigc::signal<void, S2EExecutionState*,
                 SymbolicHardwareAccessType /* type */,
                 uint64_t /* physicalAddress */,
                 unsigned /* size */,
                 bool * /* createSymbolicValue */
                 >
            onSymbolicRegisterRead;

private:

    /**
     * List of configured devices.
     * Initialized when S2E starts and valid until S2E shuts down.
     */
    DeviceDescriptors m_devices;


    uint32_t m_portMap[65536/(sizeof(uint32_t)*8)];

    /** For the VFIO plugin */
    SymbolicMemoryHook m_dmaHook;


    /** mutable because DenseSet::find doesn't have a const version */
    mutable SymbolicMemoryRegions m_symbolicMemoryRegions;

    std::map<int, void *> m_busses;
    bool m_listerners_registered;

    void onDeviceActivation(int bus_type, void *bus);

    void handleOpcodePlugUnplug(S2EExecutionState *state, bool plugIn);
    virtual void handleOpcodeInvocation(S2EExecutionState *state,
                                        uint64_t guestDataPtr,
                                        uint64_t guestDataSize);

    void onStateSwitch(S2EExecutionState *old, S2EExecutionState *newState);
};

class PciDeviceState
{
private:
    bool m_inited;
    unsigned m_currentResourceSchedule;
    unsigned m_numBars;
    klee::ref<klee::Expr> m_barSizes[PCI_NUM_REGIONS];
    klee::ref<klee::Expr> m_barEncodedSizes[PCI_NUM_REGIONS];

    const PciDeviceDescriptor *m_desc;

    template <typename T>
    void initSymb(S2EExecutionState *state, unsigned offset, const std::string &name);

public:
    PciDeviceState();
    void initialize(S2EExecutionState *state, const PciDeviceDescriptor *dev);

    klee::ref<klee::Expr> readExtendedSpace(S2EExecutionState *state, unsigned offset, unsigned size);
    klee::ref<klee::Expr> readBar(unsigned num, uint64_t originalValue);
    bool queryResource(uint64_t address, klee::ref<klee::Expr> &size);

    unsigned getCurrentResourceSchedule() const {
        return m_currentResourceSchedule;
    }

    bool incrementResourceSchedule(S2EExecutionState *state);

    friend class PciDeviceDescriptor;
};

class SymbolicHardwareState : public PluginState
{
private:

    class PageBitmap {
    private:
        llvm::BitVector array;
    public:
        PageBitmap();
        bool set(unsigned offset, unsigned length, bool b);
        bool get(unsigned offset) const;

        bool hasSymbolic() const {
            return array.any();
        }
    };

    typedef std::map<uint64_t, PageBitmap> MemoryRanges;
    MemoryRanges m_MmioMemory;

    uint32_t m_curPciCfg;

    typedef std::map<const PciDeviceDescriptor*, PciDeviceState> DeviceStateMap;
    DeviceStateMap m_pciDevices;
    bool m_symbolicPciBusEnabled;

public:

    SymbolicHardwareState();
    virtual ~SymbolicHardwareState();
    virtual SymbolicHardwareState* clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    bool setMmioRange(uint64_t physbase, uint64_t size, bool b);
    bool isMmio(uint64_t physaddr, uint64_t size) const;

    void setCurPciCfg(uint32_t cfg) {
        m_curPciCfg = cfg;
    }

    uint32_t getCurPciCfg() const {
        return m_curPciCfg;
    }

    PciDeviceState &getPciDeviceState(const PciDeviceDescriptor *dev) {
        return m_pciDevices[dev];
    }

    bool isPciBusSymbolic() const { return m_symbolicPciBusEnabled; }
    void setPciBusSymbolic(bool b) { m_symbolicPciBusEnabled = b; }

    friend class SymbolicHardware;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
