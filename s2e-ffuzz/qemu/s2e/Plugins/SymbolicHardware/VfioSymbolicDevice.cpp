///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2EExecutor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/SymbolicHardwareHook.h>
#include <klee/AddressSpace.h>
#include "VfioSymbolicDevice.h"
#include "SymbolicHardware.h"

#include <memory.h>

//#define DEBUG_VFIO

extern "C" {
PCIDevice *vfio_s2e_find_device(void);
void vfio_s2e_switch_to_symbolic(PCIDevice *pdev);
}

namespace s2e {
namespace plugins {

static klee::ref<klee::Expr> vfio_symbread(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
);

static void vfio_symbwrite(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
);

VfioDeviceDescriptor* VfioDeviceDescriptor::create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key)
{
    bool ok;
    llvm::raw_ostream &ws = plg->getWarningsStream();
    //llvm::raw_ostream &ms = plg->getInfoStream();

    std::string id = cfg->getString(key + ".id", "", &ok);
    if (!ok) {
        ws << "You must specify an id for the vfio device in " << key << ".id\n";
        exit(-1);
    }

    VfioDeviceDescriptor *ret = new VfioDeviceDescriptor(id);

    SymbolicMemoryHook hook = SymbolicMemoryHook(NULL, vfio_symbread, vfio_symbwrite, ret);
    plg->setDmaHook(hook);


    /**
     * Use symbolic values along with real concrete values comming from
     * real hardware when executing the first path.
     */
    ret->m_firstPathSymbolic = cfg->getBool(key + ".firstPathSymbolic", true);
    ret->m_symbolicDevice = false;

    ret->m_concreteDeviceActive = true;

    plg->s2e()->getCorePlugin()->onAddressSpaceChange.connect(
       sigc::mem_fun(*ret, &VfioDeviceDescriptor::onAddressSpaceChange)
    );

    plg->s2e()->getCorePlugin()->onInitializationComplete.connect(
       sigc::mem_fun(*ret, &VfioDeviceDescriptor::onInitializationComplete)
    );

    plg->s2e()->getCorePlugin()->onStateSwitch.connect(
       sigc::mem_fun(*ret, &VfioDeviceDescriptor::onStateSwitch)
    );

    plg->s2e()->getCorePlugin()->onPciDeviceMappingUpdate.connect(
        sigc::mem_fun(*ret, &VfioDeviceDescriptor::onDeviceUpdateMappings)
    );

    /**
     * This is required to ensure correct DMA on the concrete path.
     */
    klee::g_klee_address_space_preserve_concrete_buffer_address = true;

    return ret;
}

void VfioDeviceDescriptor::print(llvm::raw_ostream &os) const
{

}

void VfioDeviceDescriptor::initializeQemuDevice()
{

}

void VfioDeviceDescriptor::activateQemuDevice(void *bus)
{

}

void VfioDeviceDescriptor::onStateSwitch(S2EExecutionState *oldState, S2EExecutionState *newState)
{
    vfio_s2e_switch_to_symbolic((PCIDevice*) getDevice());

    initializeSymbolicRegions(newState);
}

void VfioDeviceDescriptor::onDeviceUpdateMappings(S2EExecutionState *state, void *pci_device,
                                              int bar_index, uint64_t old_addr)
{
    if (!m_symbolicDevice || pci_device != m_qemuDev) {
        return;
    }

    PCIDevice *d = static_cast<PCIDevice*>(pci_device);

    int i = bar_index;
    int type = d->io_regions[i].type;


    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));

    g_s2e->getDebugStream(state) << "VfioDeviceDescriptor: updating symbolic regions\n";

    if (old_addr != PCI_BAR_UNMAPPED) {
        if (type & PCI_BASE_ADDRESS_SPACE_IO) {
            hw->setSymbolicPortRange(old_addr, d->io_regions[i].size, false);
        }
    }

    if (d->io_regions[i].addr != PCI_BAR_UNMAPPED) {
        if (type & PCI_BASE_ADDRESS_SPACE_IO) {
            // Port I/O
            hw->setSymbolicPortRange(d->io_regions[i].addr, d->io_regions[i].size, true);
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor:    region " << i << " (IO) "
                                         << "addr=" << hexval(d->io_regions[i].addr) << " "
                                         << "size=" << hexval(d->io_regions[i].size) << "\n";
        } else {
            // MMIO
            // Left empty for now as we can handle I/O memory
            // accesses via the code in softmmu_template.h
            hw->setSymbolicMmioRange(d->io_regions[i].memory);
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor:    region " << i << " (MMIO) "
                                         << "addr=" << hexval(d->io_regions[i].addr) << " "
                                         << "size=" << hexval(d->io_regions[i].size) << "\n";
        }
    }
}

void VfioDeviceDescriptor::initializeSymbolicRegions(S2EExecutionState *state)
{
    if (m_symbolicDevice) {
        return;
    }

    g_s2e->getDebugStream(state) << "VfioDeviceDescriptor: initializing symbolic regions\n";

    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    PCIDevice *d = static_cast<PCIDevice*>(m_qemuDev);
    for (unsigned i = 0; i < PCI_NUM_REGIONS; ++i) {
        if (d->io_regions[i].addr == PCI_BAR_UNMAPPED || d->io_regions[i].size == 0) {
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor:    region " << i << " (UNMAPPED) "
                                         << "addr=" << hexval(d->io_regions[i].addr) << " "
                                         << "size=" << hexval(d->io_regions[i].size) << "\n";
            continue;
        }

        if (d->io_regions[i].type & PCI_BASE_ADDRESS_SPACE_IO) {
            hw->setSymbolicPortRange(d->io_regions[i].addr, d->io_regions[i].size, true);
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor:    region " << i << " (IO) "
                                         << "addr=" << hexval(d->io_regions[i].addr) << " "
                                         << "size=" << hexval(d->io_regions[i].size) << "\n";
        } else {
            //Register the whole memory region
            hw->setSymbolicMmioRange(d->io_regions[i].memory);
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor:    region " << i << " (MMIO) "
                                         << "addr=" << hexval(d->io_regions[i].addr) << " "
                                         << "size=" << hexval(d->io_regions[i].size) << "\n";
        }
    }

    m_symbolicDevice = true;
}

void VfioDeviceDescriptor::onInitializationComplete(S2EExecutionState *state)
{
    PCIDevice *pdev = vfio_s2e_find_device();
    assert(pdev);
    m_qemuDev = pdev;

    foreach2 (it, state->addressSpace.objects.begin(), state->addressSpace.objects.end()) {
        const klee::MemoryObject *mo = (*it).first;
        const klee::ObjectState *os = (*it).second;

        if (!mo->isMemoryPage) {
            continue;
        }

        if (state->addressSpace.isOwnedByUs(os)) {
            // A new page has been created.

            // Get the memory region
            uintptr_t start = (uintptr_t) memory_region_get_ram_ptr(mo->region);
            uintptr_t size = memory_region_size(mo->region);
            assert(start <= mo->address && mo->address < start + size);

            uintptr_t buffer = (uintptr_t) os->getConcreteBuffer()->get();

#ifdef DEBUG_VFIO
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor: "
                    << "mapping host page " << hexval(mo->address)
                    << " concrete buffer " << hexval(buffer)
                    << " of size " << hexval(mo->size) << " for MMIO\n";
#endif

            memory_notify_remap(mo->address - start, 0, buffer, mo->size, os->readOnly);
        }
    }

    if (m_firstPathSymbolic) {
        initializeSymbolicRegions(state);
    }
}

/**
 * Updates the IOMMU with the new pages corresponding to the current state.
 *
 * XXX: This mostly works, but there is still a race condition possible, when
 * the device does DMA after the new page has been copied but before the
 * mapping was updated in hardware. A possible solution might be to copy back
 * the content of the new page to the old one after the copy is done.
 * Need to make sure that this won't break anything.
 */
void VfioDeviceDescriptor::onAddressSpaceChange(
                        S2EExecutionState *state,
                        const klee::MemoryObject *mo,
                        const klee::ObjectState *oldState,
                        klee::ObjectState *newState)
{
    if (state->getID() != 0) {
        return;
    }

    if (!mo->isMemoryPage) {
        return;
    }

    // Get the memory region
    uintptr_t start = (uintptr_t) memory_region_get_ram_ptr(mo->region);
    uintptr_t size = memory_region_size(mo->region);
    assert(start <= mo->address && mo->address < start + size);

    if (!oldState && newState) {
        // A new page has been created.
#ifdef DEBUG_VFIO
        g_s2e->getDebugStream(state) << "VfioDeviceDescriptor: "
                << "mapping host page " << hexval(mo->address)
                << " of size " << hexval(mo->size) << " for MMIO\n";
#endif

        const klee::ConcreteBuffer *concreteBuffer = newState->getConcreteBuffer();
        memory_notify_remap(mo->address - start, 0, (uintptr_t) concreteBuffer->get(), mo->size, newState->readOnly);

    } else if (oldState && newState) {
        //Nothing to do here, the concrete buffer in the new state has
        //the same address (but the old one has changed)
        //The mapping has been changed, all subsequent DMA writes
        //should go to the new page.

#if 0
        uintptr_t oldBuffer = (uintptr_t) oldState->getConcreteBuffer()->get();
        uintptr_t newBuffer = (uintptr_t) newState->getConcreteBuffer()->get();

#ifdef DEBUG_VFIO
        g_s2e->getDebugStream(state) << "VfioDeviceDescriptor: "
                << "updating mapping of host page " << hexval(mo->address - start)
                << " of size " << hexval(mo->size) << " for MMIO "
                << " from " << hexval(oldBuffer)
                << " to " << hexval(newBuffer) << "\n";
#endif

        //Not necessary anymore, with g_klee_address_space_preserve_concrete_buffer_address
        memory_notify_remap(mo->address - start, oldBuffer, newBuffer, mo->size, oldState->readOnly);

        //Check if old and new buffer have the same content
        if (memcmp((void*) oldBuffer, (void *) newBuffer, mo->size)) {
            g_s2e->getDebugStream(state) << "VfioDeviceDescriptor:    buffers differ!\n";
        }
#endif
    }
}

static klee::ref<klee::Expr> vfio_symbread(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
)
{
#ifdef DEBUG_VFIO
    g_s2e->getDebugStream(g_s2e_state) << "vfio: dma read @" << hexval(physaddress) << " value " << value << "\n";
#endif

#if 1
    return value;
#else
    //All states read normal memory
    //TODO: return a symbolic value
    if (g_s2e_state->getID() != 0) {
        return value;
    }

    if (type != SYMB_DMA) {
        return value;
    }

    //Read the concrete value from the global shared store
    uint64_t hostAddress = g_s2e_state->mem()->getHostAddress(physaddress, PhysicalAddress);
    if (hostAddress == (uint64_t) -1) {
        assert(false);
        return value;
    }

    //XXX: endianness
    uint64_t buffer = 0;
    unsigned size = klee::Expr::getMinBytesForWidth(value->getWidth());
    memcpy(&buffer, (void*) hostAddress, size);

    g_s2e->getDebugStream(g_s2e_state) << "vfio: dma read physaddr @" << hexval(physaddress)
                                       << " hostaddr @" << hexval(hostAddress)
                                       << " writing " << hexval(buffer) << " to state-local memory\n";
    //Write it back to the state's memory, to keep both in sync
    if (!g_s2e_state->mem()->writeMemoryConcrete(physaddress, &buffer, size, PhysicalAddress)) {
        assert(false);
        return value;
    }

    klee::ref<klee::Expr> ret;
    ret = g_s2e_state->mem()->readMemory(physaddress, value->getWidth(), PhysicalAddress);
    g_s2e->getDebugStream(g_s2e_state) << "vfio: dma read @" << hexval(physaddress) << " value " << ret << "\n";
    return ret;
#endif
}

static void vfio_symbwrite(
        struct MemoryRegion *mr,
        uint64_t physaddress,
        const klee::ref<klee::Expr> &value,
        SymbolicHardwareAccessType type,
        void *opaque
)
{
#if 0
    //The caller already wrote it to the state's memory, just
    //need to update the shared memory now.
    uint64_t hostAddress = g_s2e_state->mem()->getHostAddress(physaddress, PhysicalAddress);
    assert(hostAddress != (uint64_t) -1);
    uint64_t concreteValue = g_s2e->getExecutor()->toConstant(*g_s2e_state, value, "vfio: guest writes to DMA region")->getZExtValue();

    //XXX: endianness
    unsigned size = klee::Expr::getMinBytesForWidth(value->getWidth());
    memcpy((void*) hostAddress, &concreteValue, size);
#endif
#ifdef DEBUG_VFIO
    {
        uint64_t hostAddress = g_s2e_state->mem()->getHostAddress(physaddress, PhysicalAddress);
        assert(hostAddress != (uint64_t) -1);

        g_s2e->getDebugStream(g_s2e_state) << "vfio: dma write @" << hexval(physaddress) << " value " << value <<
                                              " host_addr @" << hexval(hostAddress) << "\n";
    }
#endif
}

}
}
