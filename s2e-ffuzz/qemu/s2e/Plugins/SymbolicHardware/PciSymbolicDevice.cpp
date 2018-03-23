///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


extern "C"
{
#include "cpu.h"
#include "hw/hw.h"
#include "hw/pci_regs.h"
#include "hw/fakepci.h"
#include "hw/sysbus.h"
#include "hw/msi.h"
#include "hw/sysbus.h"
#include "memory.h"
}

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>

#include "SymbolicHardware.h"
#include "PciSymbolicDevice.h"


namespace s2e {
namespace plugins {

extern const MemoryRegionOps symbhw_io_ops;
extern const MemoryRegionOps symbhw_mmio_ops;

extern "C" {
    static void pci_symbhw_rebuild_bars(PCIDevice *device);
    static void pci_symbhw_class_init(ObjectClass *klass, void *data);
}

//XXX: This should be the same as PCIFakeState?
struct SymbolicPciDeviceState {
    PCIDevice dev;
    PciDeviceDescriptor *desc;
    MemoryRegion io[PCI_NUM_REGIONS];
};

PciDeviceDescriptor* PciDeviceDescriptor::create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key)
{
    bool ok;
    llvm::raw_ostream &ws = plg->getWarningsStream();
    llvm::raw_ostream &ms = plg->getInfoStream();

    std::string id = cfg->getString(key + ".id", "", &ok);
    assert(ok);

    uint16_t vid = cfg->getInt(key + ".vid", 0, &ok);
    if (!ok) {
        ws << "You must specify a vendor id for a symbolic PCI device!" << '\n';
        return NULL;
    }

    uint16_t pid = cfg->getInt(key + ".pid", 0, &ok);
    if (!ok) {
        ws << "You must specify a product id for a symbolic PCI device!" << '\n';
        return NULL;
    }

    uint16_t ss_vid = cfg->getInt(key + ".ss_vid", 0, &ok);
    if (!ok) {
        ms << "Defaulting to ss_vid of 0\n";
        ss_vid = 0;
    }

    uint16_t ss_id = cfg->getInt(key + ".ss_id", 0, &ok);
    if (!ok) {
        ms << "Defaulting to ss_id of 0\n";
        ss_id = 0;
    }

    uint32_t classCode = cfg->getInt(key + ".classCode", 0, &ok);
    if (!ok || classCode > 0xffffff) {
        ws << "You must specify a valid class code for a symbolic PCI device!" << '\n';
        return NULL;
    }

    uint8_t revisionId = cfg->getInt(key + ".revisionId", 0, &ok);
    if (!ok) {
        ws << "You must specify a revision id for a symbolic PCI device!" << '\n';
        return NULL;
    }

    uint8_t interruptPin = cfg->getInt(key + ".interruptPin", 0, &ok);
    if (!ok || interruptPin > 4) {
        ws << "You must specify an interrupt pin (1-4, 0 for none) for " << key << "!" << '\n';
        return NULL;
    }

    uint32_t capPM = cfg->getInt(key + ".cap_pm", 0, &ok);
    if (!ok) {
        ms << "Defaulting to capPM = 0\n";
        capPM = 0;
    } else {
        if (capPM != 0 && capPM != 1) {
            ws << "You must specify 0 or 1 for capPM, " << key << "!" << '\n';
            return NULL;
        }
    }

    uint32_t capMSI = cfg->getInt(key + ".cap_msi", 0, &ok);
    if (!ok) {
        ms << "Defaulting to capMSI = 0\n";
        capMSI = 0;
    } else {
        if (capMSI > 4096) {
            ws << "You must specify MSI >= 0 and <= 4096 for capMSI, " << key << "!" << '\n';
            return NULL;
        }
    }

    uint32_t capPCIE = cfg->getInt(key + ".cap_pcie", 0, &ok);
    if (!ok) {
        ms << "Defaulting to capPCIE = 0\n";
        capPCIE = 0;
    } else {
        if (capPCIE != 0 && capPCIE != 1) {
            ws << "You must specify 0 or 1 for capPCIE, " << key << "!" << '\n';
            return NULL;
        }
    }

    uint64_t maxPortSize = cfg->getInt(key + ".max_portio_size", 0x100, &ok);
    if (!ok) {
        ms << "Maximum size for an I/O port will be " << hexval(maxPortSize) << "\n";
    } else {
        if (maxPortSize > 0x100) {
            ws << "max_portio_size must be less than 0x100 bytes " << key << "!" << '\n';
            return NULL;
        }
    }

    uint64_t maxMmioSize = cfg->getInt(key + ".max_mmio_size", 0x10000, &ok);
    if (!ok) {
        ms << "Maximum size for an I/O port will be " << hexval(maxMmioSize) << "\n";
    }

    std::vector<PciResource> resources;

    //Reading the resource list
    ConfigFile::string_list resKeys = cfg->getListKeys(key + ".resources", &ok);
    if (!ok || resKeys.empty()) {
        ws << "You must specify at least one resource descriptor for a symbolic PCI device!" << '\n';
        return NULL;
    }

    unsigned neededBars = 0;
    foreach2(it, resKeys.begin(), resKeys.end()) {
        std::stringstream ss;
        ss << key << ".resources." << *it;

        bool isIo = cfg->getBool(ss.str() + ".isIo", false, &ok);
        if (!ok) {
            ws << "You must specify whether the resource " << ss.str() << " is IO or MMIO!" << '\n';
            return NULL;
        }

        bool isPrefetchable = cfg->getBool(ss.str() + ".isPrefetchable", false, &ok);
        if (!ok && !isIo) {
            ws << "You must specify whether the resource " << ss.str() << " is prefetchable!" << '\n';
            return NULL;
        }

        uint32_t size = cfg->getInt(ss.str() + ".size", 0, &ok);
        if (!ok || size == 0) {
            ws << "You must specify a non-null size for the resource " << ss.str() << "!" << '\n';
            return NULL;
        }

        bool is64 = cfg->getBool(ss.str() + ".is64", false, &ok);

        if (isIo && is64) {
            ws << "An I/O resource can't be 64-bits " << ss.str() << "!" << '\n';
            return NULL;
        }

        PciResource res;
        res.isIo = isIo;
        res.is64 = is64;
        res.prefetchable = isPrefetchable;
        res.size = size;
        resources.push_back(res);
        neededBars += is64 ? 2 : 1;
    }

    if (neededBars > PCI_NUM_REGIONS) {
        ws << "A PCI device can have at most 7 resource descriptors!" << '\n';
        return NULL;
    }

    PciDeviceDescriptor *ret = new PciDeviceDescriptor(id);
    ret->m_classCode = classCode;
    ret->m_pid = pid;
    ret->m_vid = vid;
    ret->m_ss_vid = ss_vid;
    ret->m_ss_id = ss_id;
    ret->m_revisionId = revisionId;
    ret->m_interruptPin = interruptPin;
    ret->m_capPM = capPM;
    ret->m_capMSI = capMSI;
    ret->m_capPCIE = capPCIE;
    ret->m_resources = resources;

    ret->m_maxPortSize = maxPortSize;
    ret->m_maxMmioSize = maxMmioSize;

    bool randomize = cfg->getBool(key + ".randomize", false);
    if (randomize) {
        ret->initRandomResourceSchedule();
    } else {
        ret->initResourceSchedule();
    }

    plg->s2e()->getCorePlugin()->onPciDeviceMappingUpdate.connect(
        sigc::mem_fun(*ret, &PciDeviceDescriptor::onDeviceUpdateMappings)
    );

    plg->s2e()->getCorePlugin()->onDeviceRegistration.connect(
        sigc::mem_fun(*ret, &PciDeviceDescriptor::initializeQemuDevice)
    );

    plg->s2e()->getCorePlugin()->onDeviceActivation.connect(
        sigc::mem_fun(*ret, &PciDeviceDescriptor::onDeviceActivation)
    );

    return ret;
}

void PciDeviceDescriptor::onDeviceActivation(int bus_type, void *bus)
{
    g_s2e->getInfoStream() << "PciDeviceDescriptor: activating device\n";
    activateQemuDevice(bus);
}

void PciDeviceDescriptor::onDeviceUpdateMappings(S2EExecutionState *state, void *pci_device,
                                              int bar_index, uint64_t old_addr)
{
    PCIDevice *d = static_cast<PCIDevice*>(pci_device);

    if (pci_device != m_qemuDev) {
        return;
    }

    int i = bar_index;
    int type = d->io_regions[i].type;


    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));

    if (old_addr != PCI_BAR_UNMAPPED) {
        if (type & PCI_BASE_ADDRESS_SPACE_IO) {
            hw->setSymbolicPortRange(old_addr, d->io_regions[i].size, false);
        }
    }

    if (d->io_regions[i].addr != PCI_BAR_UNMAPPED) {
        if (type & PCI_BASE_ADDRESS_SPACE_IO) {
            // Port I/O
            hw->setSymbolicPortRange(d->io_regions[i].addr, d->io_regions[i].size, true);
        } else {
            // MMIO
            // Left empty for now as we can handle I/O memory
            // accesses via the code in softmmu_template.h
        }
    }
}

void PciDeviceDescriptor::initResourceSchedule()
{
    ConcretePciResources r1;

    r1.count = m_resources.size();
    unsigned i = 0;
    foreach2(it, m_resources.begin(), m_resources.end()) {
        const PciResource &res = *it;

        r1.flags[i] = 0;

        if (res.isIo) {
            r1.flags[i] = PCI_BASE_ADDRESS_SPACE_IO;
            memory_region_init_io(&r1.regions[i], &symbhw_io_ops, this, "schedc_bar0_io", res.size);
        } else {
            if (res.prefetchable) {
                r1.flags[i] |= PCI_BASE_ADDRESS_MEM_PREFETCH;
            }

            if (res.is64) {
                r1.flags[i] |= PCI_BASE_ADDRESS_MEM_TYPE_64;
            }

            memory_region_init_io(&r1.regions[i], &symbhw_mmio_ops, this, "schedc_bar0_mmio", res.size);
        }

        ++i;
    }

    m_schedule.push_back(r1);

    /* Add a few more resource combinations */
    initRandomResourceSchedule();
}

void PciDeviceDescriptor::initRandomResourceSchedule()
{
    ConcretePciResources r1;
    r1.count = 1;
    r1.flags[0] = PCI_BASE_ADDRESS_SPACE_IO;
    memory_region_init_io(&r1.regions[0], &symbhw_io_ops, this, "sched0_bar0_io", m_maxPortSize);
    m_schedule.push_back(r1);

    ConcretePciResources r2;
    r2.count = 1;
    r2.flags[0] = 0;
    memory_region_init_io(&r2.regions[0], &symbhw_mmio_ops, this, "sched1_bar0_mmio", m_maxMmioSize);
    m_schedule.push_back(r2);

    ConcretePciResources r2_64;
    r2_64.count = 1;
    r2_64.flags[0] = PCI_BASE_ADDRESS_MEM_TYPE_64;
    memory_region_init_io(&r2_64.regions[0], &symbhw_mmio_ops, this, "sched1_bar01_mmio", m_maxMmioSize);
    m_schedule.push_back(r2_64);

    ConcretePciResources r3;
    r3.count = 2;
    r3.flags[0] = 0;
    r3.flags[1] = PCI_BASE_ADDRESS_SPACE_IO;
    memory_region_init_io(&r3.regions[0], &symbhw_mmio_ops, this, "sched2_bar0_mmio", m_maxMmioSize);
    memory_region_init_io(&r3.regions[1], &symbhw_io_ops, this, "sched2_bar1_io", m_maxPortSize);
    m_schedule.push_back(r3);

    ConcretePciResources r4;
    r4.count = 2;
    r4.flags[0] = PCI_BASE_ADDRESS_SPACE_IO;
    r4.flags[1] = 0;
    memory_region_init_io(&r4.regions[0], &symbhw_io_ops, this, "sched3_bar0_io", m_maxPortSize);
    memory_region_init_io(&r4.regions[1], &symbhw_mmio_ops, this, "sched3_bar1_mmio", m_maxMmioSize);
    m_schedule.push_back(r4);
}

void PciDeviceDescriptor::initializeQemuDevice()
{
    g_s2e->getDebugStream() << "PciDeviceDescriptor::initializeQemuDevice()" << '\n';

    TypeInfo fakepci_info = {
        /* The name is changed at registration time */
        .name          = m_id.c_str(),

        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(SymbolicPciDeviceState),
        .class_init    = pci_symbhw_class_init,
        .class_data    = this,
    };

    m_devInfo = new TypeInfo(fakepci_info);

    m_devInfoProperties = new Property[1];
    memset(m_devInfoProperties, 0, sizeof(Property));

    /*
    static  VMStateDescription vmstate_pci_fake = {
        .name = "fakepci",
        .version_id = 3,
        .minimum_version_id = 3,
        .minimum_version_id_old = 3,
        .fields      = (VMStateField []) {
            VMSTATE_PCI_DEVICE(dev, PCIFakeState),
            VMSTATE_END_OF_LIST()
        }
    }; */

    m_vmStateFields = new VMStateField[2];
    memset(m_vmStateFields, 0, sizeof(VMStateField)*2);
    //Replaces VMSTATE_PCI_DEVICE()
    m_vmStateFields[0].name = "dev";
    m_vmStateFields[0].size = sizeof(PCIDevice);
    if (m_capPCIE > 0) {
        m_vmStateFields[0].vmsd = &vmstate_pcie_device;
    } else {
        m_vmStateFields[0].vmsd = &vmstate_pci_device;
    }
    m_vmStateFields[0].flags = VMS_STRUCT;
    m_vmStateFields[0].offset = vmstate_offset_value(SymbolicPciDeviceState, dev, PCIDevice);


    m_vmState = new VMStateDescription();
    memset(m_vmState, 0, sizeof(VMStateDescription));

    m_vmState->name = m_id.c_str();
    m_vmState->version_id = 3,
    m_vmState->minimum_version_id = 3,
    m_vmState->minimum_version_id_old = 3,
    m_vmState->fields = m_vmStateFields;

    type_register_static(m_devInfo);
}

void PciDeviceDescriptor::activateQemuDevice(void *bus)
{
    BusState *busState = (BusState*) bus;
    if (strstr(busState->name, "pci") == NULL) {
        return;
    }

    g_s2e->getDebugStream() << "PciDeviceDescriptor: activating device " << m_id << "\n";

    PCIDevice *dev = (PCIDevice*) qdev_create((BusState*) bus, m_id.c_str());
    assert(dev);

    if (m_pluggedIn) {
        if (qdev_init(&dev->qdev) < 0) {
            g_s2e->getWarningsStream() << "PCI device " <<
                    m_id << " could not be initialized." << '\n';
            exit(-1);
        }
    }

    if (!isActive()) {
        g_s2e->getWarningsStream() << "PCI device " <<
                m_id << " is not active. Check that its ID does not collide with native QEMU devices." << '\n';
        exit(-1);
    }
}

bool PciDeviceDescriptor::readPciAddressSpace(void *buffer, uint32_t offset, uint32_t size)
{
    PCIDevice *pci = (PCIDevice*)m_qemuDev;
    assert(pci);

    if (offset + size > 256) {
        return false;
    }

    memcpy(buffer, pci->config + offset, size);
    return true;
}

PciDeviceDescriptor::PciDeviceDescriptor(const std::string &id):DeviceDescriptor(id)
{
    m_vid = 0;
    m_pid = 0;
    m_ss_id = 0;
    m_ss_vid = 0;
    m_classCode = 0;
    m_revisionId = 0;
    m_interruptPin = 0;
    m_capPM = 0;
    m_capMSI = 0;
    m_capPCIE = 0;
    m_devfn = 0;
    m_conf = NULL;
}

PciDeviceDescriptor::~PciDeviceDescriptor()
{

}

void PciDeviceDescriptor::print(llvm::raw_ostream &os) const
{
    os << "PCI Device Descriptor id=" << m_id << '\n';
    os << "VID=" << hexval(m_vid)
       << " PID=" << hexval(m_pid)
       << " SS_VID=0x" << m_ss_vid
       << " SS_ID=0x" << m_ss_id
       << " RevID=" << hexval(m_revisionId) << '\n';

    os << "Class=" << hexval(m_classCode)
       << "INT=" << hexval(m_interruptPin) << '\n';
    os << "capPM=" << hexval(m_capPM) << "\n";
    os << "capMSI=" << hexval(m_capMSI) << "\n";
    os << "capPCIE=" << hexval(m_capPCIE) << "\n";

    unsigned i=0;
    foreach2(it, m_resources.begin(), m_resources.end()) {
        const PciResource &res = *it;
        os << "R[" << i << "]: " <<
                "Size=" << hexval(res.size) << " IsIO=" << (int)res.isIo <<
                " IsPrefetchable=" << hexval(res.prefetchable) << '\n';
        ++i;
    }
    os << '\n';
}

void PciDeviceDescriptor::setInterrupt(bool state)
{
    g_s2e->getDebugStream() << "PciDeviceDescriptor::setInterrupt " << state << '\n';
    assert(m_qemuIrq);
    if (state) {
       //s2e_print_apic(env);
        qemu_irq_raise(*(qemu_irq*)m_qemuIrq);
       // s2e_print_apic(env);
    }else {
        //s2e_print_apic(env);
       qemu_irq_lower(*(qemu_irq*)m_qemuIrq);
       //s2e_print_apic(env);
    }
}

void PciDeviceDescriptor::assignIrq(void *irq)
{
    m_qemuIrq = (qemu_irq*)irq;
}

static int pci_symbhw_init(PCIDevice *pci_dev)
{
    SymbolicPciDeviceState *symb_pci_state = DO_UPCAST(SymbolicPciDeviceState, dev, pci_dev);
    uint8_t *pci_conf;

    s2e_debug_print("pci_symbhw_init\n");

    //Retrive the configuration
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);

    PciDeviceDescriptor *pci_device_desc = static_cast<PciDeviceDescriptor*>(hw->findDevice(pci_dev->name));
    assert(pci_device_desc);

    pci_device_desc->setActive(true);
    pci_device_desc->setDevFn(pci_dev->devfn);

    symb_pci_state->desc = pci_device_desc;
    pci_device_desc->setDevice(&symb_pci_state->dev);

    pci_conf = symb_pci_state->dev.config;
    pci_conf[PCI_HEADER_TYPE] = PCI_HEADER_TYPE_NORMAL; // header_type
    pci_set_byte(&pci_conf[PCI_INTERRUPT_PIN], pci_device_desc->getInterruptPin());
    pci_set_byte(&pci_conf[PCI_REVISION_ID], pci_device_desc->getRevisionId());

    // Force PCI power management to ON
    // We could add a flag for this.
    if (pci_device_desc->getCapPM() > 0) {
        int r = pci_add_capability(pci_dev, PCI_CAP_ID_PM, 0, PCI_PM_SIZEOF);
        assert (r >= 0 && "Why isn't power management working?");
    }

    if (pci_device_desc->getCapMSI() > 0) {
        // The 0 = find a valid PCI capability offset.
        // 0x50 seems to work FWIW
        // The first 64 bytes of PCI config space are
        // standardized, so 0x50 = the first byte after that.
        // If we add more capabilities this number might need
        // to be changed.
        // false = msi64bit (4th param)
        // false = msi_per_vector_mask (5th param)
        msi_init(pci_dev, 0, pci_device_desc->getCapMSI(), false, false);
    } else {
        assert (pci_device_desc->getCapMSI() == 0 && "?? MSI should be >= 0");
    }

    if (pci_device_desc->getCapPCIE() > 0) {
        // TODO:  I have no idea if we should be using PCI_EXP_TYPE_ENDPOINT
        // and I also have no idea if 0 is a reasonable "port" number.
        // We're basically am just calling this function and hoping for the best.
        int r = pcie_cap_init(pci_dev, 0, PCI_EXP_TYPE_ENDPOINT, 0);
        assert (r >= 0 && "Why isn't PCI-E working?");
    }

    if (pci_device_desc->getCapPM() > 0) {
        uint8_t cap;
        cap = pci_find_capability(pci_dev, PCI_CAP_ID_PM);
        g_s2e->getInfoStream() << "capPM offset: " << hexval(cap) << "\n";
        assert (cap != 0 && "cap PM bug.");
    }
    if (pci_device_desc->getCapMSI() > 0) {
        uint8_t cap;
        cap = pci_find_capability(pci_dev, PCI_CAP_ID_MSI);
        g_s2e->getInfoStream() << "capMSI offset: " << hexval(cap) << "\n";
        assert (cap != 0 && "cap MSI bug.");
    }
    if (pci_device_desc->getCapPCIE() > 0) {
        uint8_t cap;
        cap = pci_find_capability(pci_dev, PCI_CAP_ID_EXP);
        g_s2e->getInfoStream() << "capPCIE offset: " << hexval(cap) << "\n";
        assert (cap != 0 && "cap PCI-E bug.");
    }

    pci_dev->rebuild_bars = pci_symbhw_rebuild_bars;

    pci_symbhw_rebuild_bars(pci_dev);

    pci_device_desc->initializeSymbolicConfigurationData(g_s2e_state);

    pci_device_desc->assignIrq(&symb_pci_state->dev.irq[0]);
    hw->registerMemoryListeners();
    return 0;
}

static void pci_symbhw_rebuild_bars(PCIDevice *pci_dev)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);

    PciDeviceDescriptor *pci_device_desc = static_cast<PciDeviceDescriptor*>(hw->findDevice(pci_dev->name));
    assert(pci_device_desc);

    DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, g_s2e_state);
    PciDeviceState &pci_state = plgState->getPciDeviceState(pci_device_desc);
    unsigned schedIdx = pci_state.getCurrentResourceSchedule();
    PciDeviceDescriptor::PciResourceSchedule &sched = pci_device_desc->getSchedule();
    assert(schedIdx < sched.size());
    PciDeviceDescriptor::ConcretePciResources &res = sched[schedIdx];

    unsigned j = 0;
    for (unsigned i = 0; i < res.count && j < PCI_NUM_REGIONS; ++i, ++j) {
        int type = res.flags[i];
        pci_register_bar(pci_dev, j, type, &res.regions[i]);
        if (type & PCI_BASE_ADDRESS_MEM_TYPE_64)  {
            ++j;
        }
    }
}

void PciDeviceDescriptor::initializeSymbolicConfigurationData(S2EExecutionState *state)
{
    PCIDevice *dev = static_cast<PCIDevice*>(getDevice());
    void *concreteStore = qemu_vmalloc(0x1000);
    memcpy(concreteStore, dev->config, 0x100);
    m_conf = g_s2e->getExecutor()->addExternalObject(*state, concreteStore, 0x1000, false, true);
    m_conf->isMemoryPage = true;
    m_conf->isSplittable = false;

    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, state);
    PciDeviceState &pciState = plgState->getPciDeviceState(this);
    pciState.m_desc = this;
}

void PciDeviceDescriptor::activateSymbolicConfigurationData(S2EExecutionState *state)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);
    DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, state);

    PciDeviceState &pciState = plgState->getPciDeviceState(this);
    pciState.initialize(state, this);
}

PciDeviceState::PciDeviceState() : m_inited(false), m_currentResourceSchedule(0), m_numBars(0), m_desc(NULL)
{

}

bool PciDeviceState::incrementResourceSchedule(S2EExecutionState *state)
{
    const PciDeviceDescriptor::PciResourceSchedule &schedule = m_desc->getSchedule();
    if (m_currentResourceSchedule == schedule.size() - 1) {
        return false;
    }

    m_currentResourceSchedule++;

    PCIDevice *pci_dev = static_cast<PCIDevice*>(m_desc->getDevice());
    pci_device_enable(pci_dev, false);
    pci_clear_mappings(pci_dev);
    pci_symbhw_rebuild_bars(pci_dev);

    if (m_inited) {
        m_inited = false;
        initialize(state, m_desc);
    }


    g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: selected new resource config\n";
    const PciDeviceDescriptor::ConcretePciResources &res = schedule[m_currentResourceSchedule];
    for (unsigned i = 0; i < res.count; ++i) {
        uint32_t size = memory_region_size(&res.regions[i]);
        g_s2e->getDebugStream(g_s2e_state) << "   " << i << ": "
                << " size=" << size << " flags=" << res.flags[i] << "\n";
    }

    //Note: it is up to the caller to re-enable the device
    return true;
}

template <typename T>
void PciDeviceState::initSymb(S2EExecutionState *state, unsigned offset, const std::string &name)
{
    std::stringstream ss;
    ss << "pci_" << m_desc->getDevFn() << "_" << name;
    PCIDevice *pci_dev = static_cast<PCIDevice*>(m_desc->getDevice());
    klee::ref<klee::Expr> symRev = state->createConcolicValue<T>(ss.str(), *(T*) &pci_dev->config[offset]);
    state->mem()->writeMemory(m_desc->getConf()->address + offset, symRev, HostAddress);
}

void PciDeviceState::initialize(S2EExecutionState *state, const PciDeviceDescriptor *dev)
{
    if (m_inited) {
        return;
    }

    PCIDevice *pci_dev = static_cast<PCIDevice*>(dev->getDevice());
    state->mem()->writeMemoryConcrete(dev->getConf()->address, pci_dev->config, 0x100, HostAddress);

    const PciDeviceDescriptor::PciResourceSchedule &sched = dev->getSchedule();
    const PciDeviceDescriptor::ConcretePciResources &res = sched[m_currentResourceSchedule];

    unsigned baridx = 0;
    for (unsigned i = 0; i < res.count && baridx < PCI_NUM_REGIONS; ++i, ++baridx) {
        std::stringstream ss;
        ss << "pci_" << dev->getDevFn() << "_bar" << i << "_size";
        uint32_t size = memory_region_size(&res.regions[i]);

        klee::Expr::Width width;
        klee::ref<klee::Expr> symSize;

        bool is64 = res.flags[i] & PCI_BASE_ADDRESS_MEM_TYPE_64;
        bool isIo = res.flags[i] & PCI_BASE_ADDRESS_SPACE_IO;

        klee::ref<klee::Expr> encodedSize;

        if (!isIo && is64) {
            width = klee::Expr::Int64;
            symSize = state->createConcolicValue<uint64_t>(ss.str(), size);
            m_barSizes[baridx] = symSize;
            //m_barSizes[baridx + 1] = NULL; //do we need this?


            encodedSize = klee::SubExpr::create(symSize, klee::ConstantExpr::create(1, width));
            encodedSize = klee::NotExpr::create(encodedSize);
            encodedSize = klee::OrExpr::create(encodedSize, klee::ConstantExpr::create(pci_dev->io_regions[baridx].type, width));

            m_barEncodedSizes[baridx] = klee::ExtractExpr::create(encodedSize, 0, klee::Expr::Int32);
            m_barEncodedSizes[baridx + 1] = klee::ExtractExpr::create(encodedSize, 32, klee::Expr::Int32);
            baridx++; /* skip the next bar */
        } else {
            width = klee::Expr::Int32;
            symSize = state->createConcolicValue<uint32_t>(ss.str(), size);

            encodedSize = klee::SubExpr::create(symSize, klee::ConstantExpr::create(1, width));
            encodedSize = klee::NotExpr::create(encodedSize);
            encodedSize = klee::OrExpr::create(encodedSize, klee::ConstantExpr::create(pci_dev->io_regions[baridx].type, width));

            m_barSizes[baridx] = symSize;
            m_barEncodedSizes[baridx] = encodedSize;
        }


        klee::ref<klee::Expr> constraint = klee::UleExpr::create(symSize, klee::ConstantExpr::create(size, width));
        constraint = klee::AndExpr::create(constraint, klee::UgtExpr::create(symSize, klee::ConstantExpr::create(0, width)));
        state->addConstraint(constraint);
    }

    m_numBars = baridx;
    m_inited = true;
    m_desc = dev;

    /* Create a symbolic revision id */
    initSymb<uint8_t>(state, PCI_REVISION_ID, "revision_id");

    /* Create symbolic cap */
    initSymb<uint8_t>(state, PCI_CAPABILITY_LIST, "capability");

    /* Symbolic command reg */
    initSymb<uint16_t>(state, PCI_COMMAND, "command");

    /* Create symbolic ssid */
    initSymb<uint16_t>(state, PCI_SUBSYSTEM_VENDOR_ID, "subsystem_vid");
    initSymb<uint16_t>(state, PCI_SUBSYSTEM_ID, "subsystem_id");
}

klee::ref<klee::Expr> PciDeviceState::readExtendedSpace(S2EExecutionState *state, unsigned offset, unsigned size)
{
    std::vector <uint8_t> concreteValue(size);
    std::stringstream ss;

    ss << "pci_" << m_desc->getDevFn() << "_extspace_" << hexval(offset);
    klee::ref<klee::Expr> sym = state->createConcolicValue(ss.str(), size * 8, concreteValue);
    //state->mem()->writeMemory(dev->getConf()->address + offset, sym, HostAddress);
    return sym;
}

klee::ref<klee::Expr> PciDeviceState::readBar(unsigned num, uint64_t originalValue)
{
    assert(m_inited);
    if (num >= m_numBars) {
        return klee::ConstantExpr::create((uint32_t) PCI_BAR_UNMAPPED, klee::Expr::Int32);
    }

    klee::ref<klee::Expr> ret = klee::ConstantExpr::create(originalValue & 0xffffffff, klee::Expr::Int32);

    PCIDevice *pci_dev = static_cast<PCIDevice*>(m_desc->getDevice());

    /* Deal with 64-bits descriptors */
    if (num > 0) {
        bool isIo = pci_dev->io_regions[num - 1].type & PCI_BASE_ADDRESS_SPACE_IO;
        bool is64 = pci_dev->io_regions[num - 1].type & PCI_BASE_ADDRESS_MEM_TYPE_64;
        if (!isIo && is64) {
            uint64_t encodedSize = ~(pci_dev->io_regions[num - 1].size - 1) | pci_dev->io_regions[num - 1].type;
            if (encodedSize >> 32 == originalValue) {
                return m_barEncodedSizes[num];
            } else {
                return ret;
            }
        }
    }

    /* 32-bits case */
    uint32_t encodedSize = ~(pci_dev->io_regions[num].size - 1) | pci_dev->io_regions[num].type;
    if (originalValue == encodedSize) {
        return m_barEncodedSizes[num];
    }

    return ret;
}

bool PciDeviceState::queryResource(uint64_t address, klee::ref<klee::Expr> &size)
{
    PCIDevice *pci_dev = static_cast<PCIDevice*>(m_desc->getDevice());
    for (unsigned i = 0; i < m_numBars; ++i) {
        if (pci_dev->io_regions[i].addr == address) {
            //Can be either 32 or 64-bits wide
            if (!m_barSizes[i].isNull()) {
                size = m_barSizes[i];
            }
            return true;
        }
    }
    return false;
}

klee::ref<klee::Expr> PciDeviceDescriptor::readConfig(S2EExecutionState *state,
                                                      unsigned offset, unsigned size,
                                                      uint64_t originalValue)
{
    assert(offset + size <= m_conf->size);
    klee::ref<klee::Expr> value;

    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);
    DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, state);
    PciDeviceState &pciState = plgState->getPciDeviceState(this);

    if (offset >= PCI_BASE_ADDRESS_0 && offset < PCI_BASE_ADDRESS_5 + sizeof(uint32_t)) {
        if ((size != 4) || (offset & (sizeof(uint32_t) - 1))) {
            g_s2e->getExecutor()->terminateStateEarly(*state, "SymbolicHardware: reading a BAR must be 4 bytes-aligned");
        }
    }

    if (offset >= 0x40) {
       value = pciState.readExtendedSpace(state, offset, size);
    } else {
        switch (offset) {
            case PCI_BASE_ADDRESS_0: value = pciState.readBar(0, originalValue); break;
            case PCI_BASE_ADDRESS_1: value = pciState.readBar(1, originalValue); break;
            case PCI_BASE_ADDRESS_2: value = pciState.readBar(2, originalValue); break;
            case PCI_BASE_ADDRESS_3: value = pciState.readBar(3, originalValue); break;
            case PCI_BASE_ADDRESS_4: value = pciState.readBar(4, originalValue); break;
            case PCI_BASE_ADDRESS_5: value = pciState.readBar(5, originalValue); break;
            default: value = state->mem()->readMemory(m_conf->address + offset, size * 8, HostAddress);
        }
    }

    g_s2e->getDebugStream(g_s2e_state) << "SymbolicHardware: reading from symbolic PCI config "
            << "devfn: " << hexval(m_devfn)
            << " offset:" << hexval(offset)
            << " value: " << value << "\n";

    return value;
}

bool PciDeviceDescriptor::queryResource(S2EExecutionState *state, uint64_t address, klee::ref<klee::Expr> &size)
{
    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);
    DECLARE_PLUGINSTATE_P(hw, SymbolicHardwareState, state);
    PciDeviceState &pciState = plgState->getPciDeviceState(this);
    return pciState.queryResource(address, size);
}

static int pci_symbhw_uninit(PCIDevice *pci_dev)
{
    SymbolicPciDeviceState *d = DO_UPCAST(SymbolicPciDeviceState, dev, pci_dev);

    // PM support requires no special shutdown

    // MSI support
    if (d->desc->getCapMSI() > 0) {
        msi_uninit(pci_dev);
    }

    // PCI-E support
    if (d->desc->getCapPCIE() > 0) {
        pcie_cap_exit(pci_dev);
    }

    for (unsigned i=0; i<d->desc->getResources().size(); ++i) {
        memory_region_destroy(&d->io[i]);
    }

    return 0;
}

static void  pci_symbhw_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    PciDeviceDescriptor *pci_desc = static_cast<PciDeviceDescriptor*>(data);
    if (pci_desc->getCapPCIE() > 0) {
        k->is_express = 1;
    }

    k->init = pci_symbhw_init;
    k->exit = pci_symbhw_uninit;

    k->vendor_id = pci_desc->getVid();
    k->device_id = pci_desc->getPid();
    k->revision = pci_desc->getRevisionId();
    k->class_id = pci_desc->getClassCode();
    k->subsystem_vendor_id = pci_desc->getSsVid();
    k->subsystem_id = pci_desc->getSsId();

    dc->vmsd = pci_desc->getVmStateDescription();
    dc->props = pci_desc->getProperties();
}



}
}
