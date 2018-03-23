///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


extern "C"
{
#include "cpu.h"
#include "hw/hw.h"
#include "hw/pci.h"
#include "hw/isa.h"
#include "hw/fakepci.h"
#include "hw/sysbus.h"
#include "hw/msi.h"
#include "qemu/object.h"
#include "memory.h"
}

#include "SymbolicHardware.h"
#include <s2e/S2E.h>
#include <s2e/S2EDeviceState.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/SymbolicHardwareHook.h>
#include <klee/util/ExprUtil.h>

#include "llvm/Support/CommandLine.h"

#include "IsaSymbolicDevice.h"
#include "PciSymbolicDevice.h"

#include <inttypes.h>

#include <sstream>

extern struct CPUX86State *env;

namespace {
    //Allows bypassing the symbolic value injection.
    //All read accesses return concrete 0 values, and writes are ignored.
    llvm::cl::opt<bool>
    EnableSymbHw("s2e-enable-symbolic-hardware",
                     llvm::cl::init(true));

    llvm::cl::opt<bool>
    DebugSymbHw("s2e-debug-symbolic-hardware",
                     llvm::cl::init(false));

    //Use random values for hardware inputs
    llvm::cl::opt<bool>
    RandomizeInput("s2e-random-hardware-input",
                     llvm::cl::init(false));
}

namespace s2e {
namespace plugins {

extern "C" {
    static bool symbhw_is_symbolic(uint16_t port, void *opaque);

    static bool symbhw_is_mmio_symbolic(struct MemoryRegion* mr, uint64_t physaddr, uint64_t size, void *opaque);

    uint64_t symbhw_read(void *opaque, target_phys_addr_t addr,
                         unsigned size);
    void symbhw_write(void *opaque, target_phys_addr_t addr,
                      uint64_t data, unsigned size);

    void symbhw_mmio_write(void *opaque, target_phys_addr_t addr,
                      uint64_t data, unsigned size);

    static void symbhw_begin(MemoryListener *listener) {};
    static void symbhw_commit(MemoryListener *listener) {};
    static void symbhw_region_add(MemoryListener *listener, MemoryRegionSection *section);
    static void symbhw_region_del(MemoryListener *listener, MemoryRegionSection *section);
    static void symbhw_region_nop(MemoryListener *listener, MemoryRegionSection *section) {};
    static void symbhw_log_start(MemoryListener *listener, MemoryRegionSection *section) {};
    static void symbhw_log_stop(MemoryListener *listener, MemoryRegionSection *section) {};
    static void symbhw_log_sync(MemoryListener *listener, MemoryRegionSection *section) {};
    static void symbhw_log_global_start(MemoryListener *listener) {};
    static void symbhw_log_global_stop(MemoryListener *listener) {};
    static void symbhw_eventfd_add(MemoryListener *listener, MemoryRegionSection *section,
                                   bool match_data, uint64_t data, int fd) {};
    static void symbhw_eventfd_del(MemoryListener *listener, MemoryRegionSection *section,
                                   bool match_data, uint64_t data, int fd) {};

}


klee::ref<klee::Expr> symbhw_symbread(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
);

void symbhw_symbwrite(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
);

klee::ref<klee::Expr> symbhw_symbportread(uint16_t port, unsigned size, uint64_t concreteValue, void *opaque);
bool symbhw_symbportwrite(uint16_t port, const klee::ref<klee::Expr> &value, void *opaque);

extern const MemoryRegionOps symbhw_io_ops = {
    .read = symbhw_read,
    .write = symbhw_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

extern const MemoryRegionOps symbhw_mmio_ops = {
    .read = symbhw_read,
    .write = symbhw_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static MemoryListener s_symbolic_hardware_memory_listener = {

    .begin = symbhw_begin,
    .commit = symbhw_commit,
    .region_add = symbhw_region_add,
    .region_del = symbhw_region_del,
    .region_nop = symbhw_region_nop,
    .log_start = symbhw_log_start,
    .log_stop = symbhw_log_stop,
    .log_sync = symbhw_log_sync,
    .log_global_start = symbhw_log_global_start,
    .log_global_stop = symbhw_log_global_stop,
    .eventfd_add = symbhw_eventfd_add,
    .eventfd_del = symbhw_eventfd_del,
    .priority = 10,
};

S2E_DEFINE_PLUGIN(SymbolicHardware, "Symbolic hardware plugin for PCI/ISA devices", "SymbolicHardware",);

void SymbolicHardware::initialize()
{
    ConfigFile *cfg = s2e()->getConfig();
    llvm::raw_ostream &ws = getWarningsStream();
    bool ok;

    getInfoStream() << "======= Initializing Symbolic Hardware =======" << '\n';

    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey(), &ok);
    if (!ok || keys.empty()) {
        ws << "No symbolic device descriptor specified in " << getConfigKey() << "." <<
                " S2E will start without symbolic hardware." << '\n';
        return;
    }

    foreach2(it, keys.begin(), keys.end()) {
        std::stringstream ss;
        ss << getConfigKey() << "." << *it;
        DeviceDescriptor *dd = DeviceDescriptor::create(this, cfg, ss.str());
        if (!dd) {
            ws << "Failed to create a symbolic device for " << ss.str() << '\n';
            exit(-1);
        }

        dd->print(getInfoStream());
        m_devices.insert(dd);
    }

    s2e()->getCorePlugin()->onStateSwitch.connect(
        sigc::mem_fun(*this, &SymbolicHardware::onStateSwitch)
    );

    //Reset all symbolic bits for now
    memset(m_portMap, 0, sizeof(m_portMap));

    if (EnableSymbHw) {
        g_symbolicPortHook = SymbolicPortHook(symbhw_is_symbolic, symbhw_symbportread, symbhw_symbportwrite, this);
        g_symbolicMemoryHook = SymbolicMemoryHook(symbhw_is_mmio_symbolic, symbhw_symbread, symbhw_symbwrite, this);
        SymbolicHardwareHookEnableMmioCallbacks(true);
    }else {
        SymbolicHardwareHookEnableMmioCallbacks(false);
    }

    m_listerners_registered = false;
}

void SymbolicHardware::registerMemoryListeners()
{
    if (!m_listerners_registered) {
        memory_listener_register(&s_symbolic_hardware_memory_listener, NULL);
        m_listerners_registered = true;
    }
}

//XXX: Do it per-state!
void SymbolicHardware::setSymbolicPortRange(uint16_t start, unsigned size, bool isSymbolic)
{
    assert(start + size <= 0x10000 && start+size>=start);
    for(unsigned i = start; i<start+size; i++) {
        uint16_t idx = i/(sizeof(m_portMap[0])*8);
        uint16_t mod = i%(sizeof(m_portMap[0])*8);

        if (isSymbolic) {
            m_portMap[idx] |= 1<<mod;
        }else {
            m_portMap[idx] &= ~(1<<mod);
        }
    }
}

bool SymbolicHardware::isSymbolic(uint16_t port) const
{
    uint16_t idx = port/(sizeof(m_portMap[0])*8);
    uint16_t mod = port%(sizeof(m_portMap[0])*8);
    return m_portMap[idx] & (1<<mod);
}

//This can be used in two cases:
//1: On device registration, to map the MMIO registers
//2: On DMA memory registration, in conjunction with the OS annotations.
bool SymbolicHardware::setSymbolicMmioRange(S2EExecutionState *state, uint64_t physaddr, uint64_t size)
{
    getDebugStream() << "SymbolicHardware: adding MMIO range " << hexval(physaddr)
            << " length=" << hexval(size) << '\n';

    DECLARE_PLUGINSTATE(SymbolicHardwareState, state);

    if (!plgState->setMmioRange(physaddr, size, true)) {
        getDebugStream(state) << "  Could not map MMIO range\n";
        return false;
    }
    return true;
}

void SymbolicHardware::setSymbolicMmioRange(struct MemoryRegion *mr)
{
    m_symbolicMemoryRegions.insert(mr);
}

//XXX: report already freed ranges
bool SymbolicHardware::resetSymbolicMmioRange(S2EExecutionState *state, uint64_t physaddr, uint64_t size)
{
    DECLARE_PLUGINSTATE(SymbolicHardwareState, state);

    if (!plgState->setMmioRange(physaddr, size, false)) {
        getDebugStream(state) << "  Could not unmap MMIO range\n";
        return false;
    }

    return true;
}

void SymbolicHardware::resetSymbolicMmioRange(struct MemoryRegion *mr)
{
    m_symbolicMemoryRegions.erase(mr);
}

bool SymbolicHardware::isMmioSymbolic(struct MemoryRegion *mr, uint64_t physaddress, uint64_t size) const
{
    DECLARE_PLUGINSTATE_CONST(SymbolicHardwareState, g_s2e_state);

    if (mr) {
        if (mr->ops == &symbhw_mmio_ops) {
            return true;
        }

        if (m_symbolicMemoryRegions.find(mr) != m_symbolicMemoryRegions.end()) {
            return true;
        }
    }

    bool b = plgState->isMmio(physaddress, size);
    //getDebugStream() << "isMmioSymbolic: 0x" << std::hex << physaddress << " res=" << b << '\n';
    return b;
}

static bool symbhw_is_symbolic(uint16_t port, void *opaque)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(opaque);
    return hw->isSymbolic(port);
}


static bool symbhw_is_mmio_symbolic(struct MemoryRegion* mr, uint64_t physaddr, uint64_t size, void *opaque)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(opaque);
    return hw->isMmioSymbolic(mr, physaddr, size);
}

bool SymbolicHardware::isRunningConcreteHardware() const
{
    bool ret = false;
    foreach2 (it, m_devices.begin(), m_devices.end()) {
        ret |= (*it)->isConcreteHardware();
    }
    return ret;
}


DeviceDescriptor *SymbolicHardware::findDevice(const std::string &name) const
{
    DeviceDescriptor dd(name);
    DeviceDescriptors::const_iterator it = m_devices.find(&dd);
    if (it != m_devices.end()) {
        return *it;
    }
    return NULL;
}

void SymbolicHardware::onStateSwitch(S2EExecutionState *old, S2EExecutionState *newState)
{
    DECLARE_PLUGINSTATE(SymbolicHardwareState, newState);
    if (plgState->isPciBusSymbolic()) {
        setSymbolicPortRange(0xcfc, 4, 1);
        setSymbolicPortRange(0xcf8, 4, 1);
    } else {
        setSymbolicPortRange(0xcfc, 4, 0);
        setSymbolicPortRange(0xcf8, 4, 0);
    }
}

void SymbolicHardware::onDeviceActivation(int bus_type, void *bus)
{
    getInfoStream() << "SymbolicHardware: activating symbolic devices...\n";
    m_busses[bus_type] = bus;
}

void SymbolicHardware::handleOpcodePlugUnplug(S2EExecutionState *state, bool plugIn)
{
    const char *what = plugIn ? "plugging" : "unplugging";
    foreach2(it, m_devices.begin(), m_devices.end()) {
        DeviceState *dev = static_cast<DeviceState*>((*it)->getDevice());
        getDebugStream(state) << "SymbolicHardware: " << what << " "
                << (*it)->getId() << "\n";

        if ((*it)->isPci()) {
            PCIDevice *pci_dev = reinterpret_cast<PCIDevice*>(dev);
            pci_device_enable(pci_dev, plugIn);
        }
    }
}

void SymbolicHardware::handleOpcodeInvocation(S2EExecutionState *state,
                                    uint64_t guestDataPtr,
                                    uint64_t guestDataSize)
{
    S2E_SYMBHW_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) <<
                "SymbolicHardware: mismatched S2E_SYMBHW_COMMAND size "
                "got " << guestDataSize << " expected " << sizeof(command) << "\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) <<
                "SymbolicHardware: could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case SYMBHW_PLUG_IN: {
            handleOpcodePlugUnplug(state, true);
        } break;

        case SYMBHW_HAS_PCI: {
            foreach2(it, m_devices.begin(), m_devices.end()) {
                if ((*it)->isPci()) {
                    command.HasPci = 1;
                    state->mem()->writeMemoryConcrete(guestDataPtr, &command, sizeof(command));
                    break;
                }
            }
        } break;

        case SYMBHW_UNPLUG: {
            handleOpcodePlugUnplug(state, false);
        } break;

        case SYMBHW_REGISTER_DMA_MEMORY: {
            getDebugStream(state) << "SymbolicHardware: registering DMA region @"
                                            << hexval(command.Memory.PhysicalAddress)
                                            << " of size " << hexval(command.Memory.Size) << "\n";
            setSymbolicMmioRange(state, command.Memory.PhysicalAddress, command.Memory.Size);
            //We must flush the TLB, so that the next access can be taken into account
            tlb_flush(state->getConcreteCpuState(), 1);
        } break;

        case SYMBHW_UNREGISTER_DMA_MEMORY: {
            getDebugStream(state) << "SymbolicHardware: unregistering DMA region @"
                                        << hexval(command.Memory.PhysicalAddress)
                                        << " of size " << hexval(command.Memory.Size) << "\n";
            resetSymbolicMmioRange(state, command.Memory.PhysicalAddress, command.Memory.Size);
            //We must flush the TLB, so that the next access can be taken into account
            tlb_flush(state->getConcreteCpuState(), 1);
        } break;

        case SYMBHW_INJECT_INTERRUPT: {
                foreach2(it, m_devices.begin(), m_devices.end()) {
                    if ((*it)->isPci()) {
                        PciDeviceDescriptor *pci = static_cast<PciDeviceDescriptor*>(*it);
                        getDebugStream(state) << "SymbolicHardware: injecting interrupt for "
                                "device " << pci->getId() << " state=" << command.InterruptLevel << "\n";
                        pci->setInterrupt((bool) command.InterruptLevel);
                        break;
                    }
                }
        } break;

        //XXX: this will affect all the states
        case SYMBHW_ACTIVATE_SYMBOLIC_PCI_BUS: {
            bool hasPci = false;
            foreach2(it, m_devices.begin(), m_devices.end()) {
                if ((*it)->isPci()) {
                    PciDeviceDescriptor *pci = static_cast<PciDeviceDescriptor*>(*it);
                    getDebugStream(state) << "SymbolicHardware: activating symbolic config space for "
                            "device " << pci->getId() << "\n";

                    pci->activateSymbolicConfigurationData(state);
                    hasPci = true;
                }

                if (hasPci) {
                    DECLARE_PLUGINSTATE(SymbolicHardwareState, state);
                    plgState->setPciBusSymbolic(true);
                    setSymbolicPortRange(0xcfc, 4, 1);
                    setSymbolicPortRange(0xcf8, 4, 1);
                }
            }
        } break;

        case SYMBHW_DEACTIVATE_SYMBOLIC_PCI_BUS: {
            DECLARE_PLUGINSTATE(SymbolicHardwareState, state);
            plgState->setPciBusSymbolic(false);
            setSymbolicPortRange(0xcfc, 4, 0);
            setSymbolicPortRange(0xcf8, 4, 0);
        } break;

        case SYMBHW_QUERY_RESOURCE_SIZE: {
            foreach2(it, m_devices.begin(), m_devices.end()) {
                if ((*it)->isPci()) {
                    PciDeviceDescriptor *pci = static_cast<PciDeviceDescriptor*>(*it);
                    klee::ref<klee::Expr> size;
                    if (!pci->queryResource(state, command.Resource.PhysicalAddress, size)) {
                        continue;
                    }

                    getDebugStream(state) << "SymbolicHardware: resource "
                            << hexval(command.Resource.PhysicalAddress)
                            <<  " of device " << pci->getId()
                            << " is " << size << "\n";

                    if (!state->mem()->writeMemory(guestDataPtr + offsetof(S2E_SYMBHW_COMMAND, Resource.Size), size)) {
                        getDebugStream(state) << "SymbolicHardware: could not write result for SYMBHW_QUERY_RESOURCE_SIZE\n";
                    }

                    break;
                }
            }
        } break;

        case SYMBHW_SELECT_NEXT_PCI_CONFIG: {
            getDebugStream(state) << "SymbolicHardware: selecting next hw config\n";

            DECLARE_PLUGINSTATE(SymbolicHardwareState, state);
            foreach2(it, m_devices.begin(), m_devices.end()) {
                if ((*it)->isPci()) {
                    PciDeviceDescriptor *pci = static_cast<PciDeviceDescriptor*>(*it);
                    PciDeviceState &pciState = plgState->getPciDeviceState(pci);
                    bool b = pciState.incrementResourceSchedule(state);
                    command.SelectNextConfigSuccess = b;
                    if (!state->mem()->writeMemoryConcrete(guestDataPtr, &command, sizeof(command))) {
                        getDebugStream(state) << "SymbolicHardware: could not write result for SYMBHW_SELECT_NEXT_PCI_CONFIG";
                    }

                    break;
                }
            }
        } break;

        case SYMBHW_GET_CURRENT_PCI_CONFIG: {
            getDebugStream(state) << "SymbolicHardware: SYMBHW_GET_CURRENT_PCI_CONFIG\n";
            DECLARE_PLUGINSTATE(SymbolicHardwareState, state);
            unsigned index = 0;
            unsigned requestedIndex = command.DeviceIndex;
            command.CurrentConfig = (uint64_t) -1;

            foreach2(it, m_devices.begin(), m_devices.end()) {
                if (!(*it)->isPci()) {
                    continue;
                }
                if (index == requestedIndex) {
                    PciDeviceDescriptor *pci = static_cast<PciDeviceDescriptor*>(*it);
                    PciDeviceState &pciState = plgState->getPciDeviceState(pci);
                    command.CurrentConfig = pciState.getCurrentResourceSchedule();
                    getDebugStream(state) << "   current config is " << command.CurrentConfig << "\n";
                    break;
                }
                ++index;
            }

            if (!state->mem()->writeMemoryConcrete(guestDataPtr, &command, sizeof(command))) {
                getDebugStream(state) << "SymbolicHardware: could not write result for SYMBHW_GET_CURRENT_PCI_CONFIG";
            }
        } break;

        default: {
            getDebugStream(state) << "SymbolicHardware: "
                    << "Invalid command " << hexval(command.Command) << "\n";
        }
    }
}


PciDeviceDescriptor *SymbolicHardware::getPciDevice(uint32_t cmd) const
{
    if (!(cmd & 0x80000000)) {
        return NULL;
    }

    uint32_t curFcn = (cmd >> 8) & 0x7;
    uint32_t curDev = (cmd >> 11) & 0x1f;
    uint32_t curBus = (cmd >> 16) & 0xff;

    //XXX: Only devices on bus 0 can be symbolic for now
    if (curBus != 0) {
        return NULL;
    }

    uint32_t devFn = PCI_DEVFN(curDev, curFcn);

    foreach2(it, m_devices.begin(), m_devices.end()) {
        if (!(*it)->isPci()) {
            continue;
        }

        PciDeviceDescriptor *desc = static_cast<PciDeviceDescriptor*>(*it);
        if (desc->getDevFn() == devFn) {
            PCIDevice *pci_dev = static_cast<PCIDevice *>(desc->getDevice());
            if (pci_dev->enabled) {
                return desc;
            }
        }
    }
    return NULL;
}

SymbolicHardware::~SymbolicHardware()
{
    foreach2(it, m_devices.begin(), m_devices.end()) {
        delete *it;
    }
}


/////////////////////////////////////////////////////////////////////
/* Dummy I/O functions for symbolic devices. Unused for now. */
uint64_t symbhw_read(void *opaque, target_phys_addr_t addr,
                     unsigned size) {
    g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: "
            << "read " << hexval(addr) << " size " << hexval(size) << "\n";

    if (RandomizeInput) {
        return rand();
    }
    return 0;
}

void symbhw_write(void *opaque, target_phys_addr_t addr,
                  uint64_t data, unsigned size) {

    g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: "
            << "write " << hexval(addr) << " size " << hexval(size) << "\n";
    return;
}

void symbhw_mmio_write(void *opaque, target_phys_addr_t addr,
                  uint64_t data, unsigned size) {

    //Store the write locally, to reuse them as concolic values.
    g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: "
            << "write " << hexval(addr) << " size " << hexval(size) << "\n";
    return;
}


bool SymbolicHardware::isDerivedFromDmaMemory(S2EExecutionState *state, const klee::ref<klee::Expr> &address,
                            llvm::SmallVector<std::pair<const klee::Array*, uint64_t>, 2> &physicalAddresses)
{
    std::vector<const klee::Array*> results;
    klee::findSymbolicObjects(address, results);
    foreach2(it, results.begin(), results.end()) {
        const klee::Array *a = *it;
        std::string::size_type pos = a->getName().find("dmaread_");
        if (pos == std::string::npos) {
            continue;
        }

        //Get the physical address appended to the address
        uint64_t physaddr;
        sscanf(a->getName().c_str() + pos, "dmaread_0x%" PRIx64, &physaddr);
        physicalAddresses.push_back(std::make_pair(a, physaddr));
    }

    return physicalAddresses.size() > 0;
}

klee::ref<klee::Expr> SymbolicHardware::createExpression(S2EExecutionState *state,
                                                         SymbolicHardwareAccessType type, uint64_t address, unsigned size,
                                                         const std::vector<uint8_t> &concolicValue)
{
    bool createVariable = true;
    onSymbolicRegisterRead.emit(state, type, address, size, &createVariable);

    std::stringstream ss;
    switch (type) {
        case SYMB_MMIO: ss << "iommuread_"; break;
        case SYMB_DMA: ss << "dmaread_"; break;
        case SYMB_PORT: ss << "portread_"; break;
    }

    //XXX: avoid double-conversion in parents
    union {
        uint64_t value;
        uint8_t array[8];
    };

    value = 0;
    assert(concolicValue.size() <= 8);
    for (unsigned i = 0; i < concolicValue.size(); ++i) {
        array[i] = concolicValue[i];
    }

    ss << hexval(address) << "@" << hexval(state->getPc());

    g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: "
            << ss.str() << " size " << hexval(size) << " value=" << hexval(value)
            << " sym=" << (createVariable ? "yes":"no")
            << "\n";

    if (createVariable) {
        return state->createConcolicValue(ss.str(), size * 8, concolicValue);
    } else {
        return klee::ConstantExpr::create(value, size * 8);
    }
}

static void SymbHwGetConcolicVector(uint64_t in, std::vector<uint8_t> &out)
{
    union {
        //XXX: assumes little endianness!
        uint64_t value;
        uint8_t concolicArray[8];
    };

    value = in;
    for (unsigned i = 0; i < out.size(); ++i) {
        out[i] = concolicArray[i];
    }
}

klee::ref<klee::Expr> symbhw_symbportread(uint16_t port, unsigned size, uint64_t concreteValue, void *opaque)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(opaque);

    std::vector<uint8_t> concolicValue(size);
    SymbHwGetConcolicVector(concreteValue, concolicValue);

    klee::ref<klee::Expr> originalValue = klee::ExtractExpr::create(klee::ConstantExpr::create(concreteValue, 64), 0, size * 8);

    if (DebugSymbHw) {
        g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: reading from port "
                << hexval(port)  << " value: " << originalValue << "\n";
    }

    if ((port & ~0x3) == 0xcf8) {
        //Return the original value
        return originalValue;
    } else if ((port & ~0x3) == 0xcfc) {
        //0xcfc: PCI data port
        DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, g_s2e_state);
        uint32_t curCmd = plgState->getCurPciCfg();

        //Check this corresponds to a symbolic device
        PciDeviceDescriptor *desc = hw->getPciDevice(curCmd);
        if (desc) {
            uint32_t curOffset = (curCmd & 0xff);
            klee::ref<klee::Expr> dword0 = desc->readConfig(g_s2e_state, curOffset & ~3, 4, concreteValue);

            unsigned sp = port & 3;
            unsigned maxsize = std::min(size, 4 - sp);
            unsigned overflow = size - maxsize;
            klee::ref<klee::Expr> ret = klee::ExtractExpr::create(dword0, (port & 3) * 8, maxsize * 8);

            if (overflow > 0) {
                //The I/O overlaps with some non-PCI ports.
                //Drivers should not do that.
                g_s2e->getExecutor()->terminateStateEarly(*g_s2e_state, "SymbolicHardware: I/O access overflows from PCI region");
            }

            return ret;
        } else {
            //Return the original value for now
            return originalValue;
        }
    }

    return  hw->createExpression(g_s2e_state, SYMB_PORT, port, size, concolicValue);
}

bool symbhw_symbportwrite(uint16_t port, const klee::ref<klee::Expr> &value, void *opaque)
{
    if (DebugSymbHw) {
        g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: writing to port "
                << hexval(port)  << " value: " << value << "\n";
    }

    SymbolicHardware *hw = static_cast<SymbolicHardware*>(opaque);

    if ((port & ~0x3) == 0xcf8) {
        //0xcf8: PCI config port
        if (DebugSymbHw) {
            g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: writing to PCI config port " << value << "\n";
        }

        if (value->getWidth() != 32 || (port & 3)) {
            //QEMU (and PCI too?) assumes that writes are always aligned here
            g_s2e->getExecutor()->terminateStateEarly(*g_s2e_state, "SymbolicHardware: incorrect access to PCI command port");
        }

        DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, g_s2e_state);

        klee::ref<klee::ConstantExpr> ce = g_s2e->getExecutor()->toConstant(*g_s2e_state, value, "Write to PCI cfg reg");
        plgState->setCurPciCfg(ce->getZExtValue());
        return true;

    } else if ((port & ~0x3) == 0xcfc) {
        //0xcfc: PCI data port
        //XXX: remove code duplication
        //Write the value to the config space, if it's a symbolic device
        DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, g_s2e_state);
        uint32_t curCmd = plgState->getCurPciCfg();

        //Check this corresponds to a symbolic device
        bool callOriginal = true;
        PciDeviceDescriptor *desc = hw->getPciDevice(curCmd);
        if (desc) {
            uint32_t curOffset = (curCmd & 0xff);
            //Stuff in the extended space doesn't matter
            if (curOffset >= 0x40) {
                callOriginal = false;
            }
        }

        return callOriginal;
    }

    if (hw->isSymbolic(port)) {
        return false;
    }
    return true;
}

klee::ref<klee::Expr> symbhw_symbread(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(opaque);
    unsigned size = klee::Expr::getMinBytesForWidth(value->getWidth());
    std::vector<uint8_t> concolicValue(size);

    if (type == SYMB_DMA) {
        //XXX: make reads symbolic
        if (hw->getDmaHook().readable()) {
            return hw->getDmaHook().read(mr, physaddress, value, type);
        }
    }

    uint64_t concreteValue = g_s2e->getExecutor()->toConstantSilent(*g_s2e_state, value)->getZExtValue();
    SymbHwGetConcolicVector(concreteValue, concolicValue);


    //TODO: redirect to the VFIO plugin if necessary (always read from shared ram on dma, only if in state 0).
    //XXX: storing symbolic values in shared dma ram there will force concretizations

    /* Initialize with a new symbolic value */
    return hw->createExpression(g_s2e_state, type, physaddress, size, concolicValue);
}

void symbhw_symbwrite(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(opaque);

    if (type == SYMB_DMA) {
        if (hw->getDmaHook().writable()) {
            hw->getDmaHook().write(mr, physaddress, value, type);
        }
    }
}

//////////////////////////////////////////////////////////////

static void symbhw_region_add(MemoryListener *listener, MemoryRegionSection *section)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);

    if (section->mr->ops != &symbhw_mmio_ops) {
        return;
    }

    //DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, g_s2e_state);
}

static void symbhw_region_del(MemoryListener *listener, MemoryRegionSection *section)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);

    if (section->mr->ops != &symbhw_mmio_ops) {
        return;
    }

    //DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, g_s2e_state);
}

//////////////////////////////////////////////////////////////
//Holds per-state information.


SymbolicHardwareState::SymbolicHardwareState()
{
    m_curPciCfg = 0;
    m_symbolicPciBusEnabled = false;
}

SymbolicHardwareState::~SymbolicHardwareState()
{

}

SymbolicHardwareState* SymbolicHardwareState::clone() const
{
    return new SymbolicHardwareState(*this);
}

PluginState *SymbolicHardwareState::factory(Plugin *p, S2EExecutionState *s)
{
    return new SymbolicHardwareState();
}

bool SymbolicHardwareState::setMmioRange(uint64_t physbase, uint64_t size, bool b)
{
    uint64_t addr = physbase;
    while(size > 0) {
        MemoryRanges::iterator it = m_MmioMemory.find(addr & TARGET_PAGE_MASK);
        if (it == m_MmioMemory.end()) {
            if (!b) {
                //No need to reset anything,
                //Go to the next page
                uint64_t leftover = TARGET_PAGE_SIZE - (addr & (TARGET_PAGE_SIZE-1));
                addr += leftover;
                size -= leftover > size ? size : leftover;
                continue;
            }else {
                //Need to create a new page
                m_MmioMemory[addr & TARGET_PAGE_MASK] = PageBitmap();
                it = m_MmioMemory.find(addr & TARGET_PAGE_MASK);
            }
        }

        uint32_t offset = addr & (TARGET_PAGE_SIZE-1);
        uint32_t mysize = offset + size > TARGET_PAGE_SIZE ? TARGET_PAGE_SIZE - offset : size;

        bool fc = (*it).second.set(offset, mysize, b);
        if (fc) {
            //The entire page is concrete, do not need to keep it in the map
            m_MmioMemory.erase(addr & TARGET_PAGE_MASK);
        }

        size -= mysize;
        addr += mysize;
    }

    return true;
}


bool SymbolicHardwareState::isMmio(uint64_t physaddr, uint64_t size) const
{
    while (size > 0) {
        MemoryRanges::const_iterator it = m_MmioMemory.find(physaddr & TARGET_PAGE_MASK);
        if (it == m_MmioMemory.end()) {
            uint64_t leftover = TARGET_PAGE_SIZE - (physaddr & (TARGET_PAGE_SIZE-1));
            physaddr += leftover;
            size -= leftover > size ? size : leftover;
            continue;
        }

        if (((physaddr & (TARGET_PAGE_SIZE-1)) == 0) && size>=TARGET_PAGE_SIZE) {
            if ((*it).second.hasSymbolic()) {
                return true;
            }
            size-=TARGET_PAGE_SIZE;
            physaddr+=TARGET_PAGE_SIZE;
            continue;
        }

        bool b = (*it).second.get(physaddr & (TARGET_PAGE_SIZE-1));
        if (b) {
            return true;
        }

        size--;
        physaddr++;
    }
    return false;
}

///////////////////////////////////////////////
SymbolicHardwareState::PageBitmap::PageBitmap() : array(TARGET_PAGE_SIZE) {

}

//Returns true if the resulting range is fully concrete
bool SymbolicHardwareState::PageBitmap::set(unsigned offset, unsigned length, bool b) {
    assert(offset <= TARGET_PAGE_SIZE && offset + length <= TARGET_PAGE_SIZE);

    for (unsigned i=offset; i<offset + length; ++i) {
        array[i] = b;
    }

    return array.none();
}

bool SymbolicHardwareState::PageBitmap::get(unsigned offset) const {
    assert(offset < TARGET_PAGE_SIZE);
    return array[offset];
}

} // namespace plugins
} // namespace s2e
