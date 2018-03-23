///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


extern "C"
{
#include "cpu.h"
#include "hw/hw.h"
#include "hw/isa.h"
#include "hw/sysbus.h"
#include "memory.h"
}

#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "SymbolicHardware.h"
#include "IsaSymbolicDevice.h"

namespace s2e {
namespace plugins {

struct SymbolicIsaDeviceState {
    ISADevice dev;
    IsaDeviceDescriptor *desc;
    qemu_irq qirq;
    MemoryRegion io;
};

extern "C" {
    static void isa_symbhw_class_init(ObjectClass *klass, void *data);
}

extern const MemoryRegionOps symbhw_io_ops;

IsaDeviceDescriptor::IsaDeviceDescriptor(const std::string &id, const IsaResource &res):DeviceDescriptor(id)
{
    m_isaResource = res;
    m_isaInfo = NULL;
    m_isaProperties = NULL;
}

void IsaDeviceDescriptor::initializeQemuDevice()
{
    g_s2e->getDebugStream() << "IsaDeviceDescriptor::initializeQemuDevice()" << '\n';

    static TypeInfo fakeisa_info = {
        /* The name is changed at registration time */
        .name          = m_id.c_str(),
        .parent        = TYPE_ISA_DEVICE,
        .instance_size = sizeof(SymbolicIsaDeviceState),
        .class_init    = isa_symbhw_class_init,
        .class_data    = this,
    };

    m_isaInfo = new TypeInfo(fakeisa_info);

    m_isaProperties = new Property[1];
    memset(m_isaProperties, 0, sizeof(Property)*1);

    /*
    static const VMStateDescription vmstate_isa_fake = {
        .name = "...",
        .version_id = 3,
        .minimum_version_id = 3,
        .minimum_version_id_old = 3,
        .fields      = (VMStateField []) {
            VMSTATE_END_OF_LIST()
        }
    };*/

    m_vmStateFields = new VMStateField[1];
    memset(m_vmStateFields, 0, sizeof(VMStateField)*1);

    m_vmState = new VMStateDescription();
    memset(m_vmState, 0, sizeof(VMStateDescription));

    m_vmState->name = m_id.c_str();
    m_vmState->version_id = 3,
    m_vmState->minimum_version_id = 3,
    m_vmState->minimum_version_id_old = 3,
    m_vmState->fields = m_vmStateFields;

    type_register_static(m_isaInfo);
}

void IsaDeviceDescriptor::activateQemuDevice(void *bus)
{
    BusState *busState = (BusState*) bus;
    if (strstr(busState->name, "isa") == NULL) {
        return;
    }

    g_s2e->getDebugStream() << "IsaDeviceDescriptor: activating device " << m_id << "\n";

    isa_create_simple((ISABus*)bus, m_id.c_str());

    if (!isActive()) {
        g_s2e->getWarningsStream() << "ISA device " <<
                m_id << " is not active. Check that its ID does not collide with native QEMU devices." << '\n';
        exit(-1);
    }
}

IsaDeviceDescriptor::~IsaDeviceDescriptor()
{
    if (m_isaInfo) {
        delete m_isaInfo;
    }
    if (m_isaProperties) {
        delete [] m_isaProperties;
    }
}

void IsaDeviceDescriptor::print(llvm::raw_ostream &os) const
{
    os << "ISA Device Descriptor id=" << m_id << '\n';
    os << "Base=" << hexval(m_isaResource.portBase)
       << " Size=" << hexval(m_isaResource.portSize) << '\n';
    os << '\n';
}

IsaDeviceDescriptor* IsaDeviceDescriptor::create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key)
{
    bool ok;
    llvm::raw_ostream &ws = plg->getWarningsStream();

    std::string id = cfg->getString(key + ".id", "", &ok);
    assert(ok);

    uint64_t start = cfg->getInt(key + ".start", 0, &ok);
    if (!ok || start > 0xFFFF) {
        ws << "The base address of an ISA device must be between 0x0 and 0xffff." << '\n';
        return NULL;
    }

    uint16_t size = cfg->getInt(key + ".size", 0, &ok);
    if (!ok) {
        return NULL;
    }

    if (start + size > 0x10000) {
        ws << "An ISA address range must not exceed 0xffff." << '\n';
        return NULL;
    }

    uint8_t irq =  cfg->getInt(key + ".irq", 0, &ok);
    if (!ok || irq > 15) {
        ws << "You must specify an IRQ between 0 and 15 for the ISA device." << '\n';
        return NULL;
    }

    IsaResource r;
    r.portBase = start;
    r.portSize = size;
    r.irq = irq;

    IsaDeviceDescriptor *ret = new IsaDeviceDescriptor(id, r);

    plg->s2e()->getCorePlugin()->onDeviceRegistration.connect(
        sigc::mem_fun(*ret, &IsaDeviceDescriptor::initializeQemuDevice)
    );

    plg->s2e()->getCorePlugin()->onDeviceActivation.connect(
        sigc::mem_fun(*ret, &IsaDeviceDescriptor::onDeviceActivation)
    );

    return ret;
}

void IsaDeviceDescriptor::onDeviceActivation(int bus_type, void *bus)
{
    g_s2e->getInfoStream() << "IsaDeviceDescriptor: activating symbolic device\n";
    activateQemuDevice(bus);
}

void IsaDeviceDescriptor::setInterrupt(bool state)
{
    g_s2e->getDebugStream() << "IsaDeviceDescriptor::setInterrupt " << state << '\n';
    assert(m_qemuIrq);
    if (state) {
       qemu_irq_raise(*(qemu_irq*)m_qemuIrq);
    }else {
       qemu_irq_lower(*(qemu_irq*)m_qemuIrq);
    }
}

void IsaDeviceDescriptor::assignIrq(void *irq)
{
    m_qemuIrq = irq;
}


/////////////////////////////////////////////////////////////////////
static int isa_symbhw_init(ISADevice *dev)
{
    s2e_debug_print("isa_symbhw_init\n");

    SymbolicIsaDeviceState *symb_isa_state = DO_UPCAST(SymbolicIsaDeviceState, dev, dev);

    SymbolicHardware *hw = static_cast<SymbolicHardware*>(g_s2e->getPlugin("SymbolicHardware"));
    assert(hw);

    const char *devName = object_class_get_name(dev->qdev.parent_obj.klass);
    IsaDeviceDescriptor *isa_device_desc = static_cast<IsaDeviceDescriptor*>(hw->findDevice(devName));
    assert(isa_device_desc);

    symb_isa_state->desc = isa_device_desc;
    isa_device_desc->setActive(true);
    isa_device_desc->setDevice(dev);

    uint32_t size = isa_device_desc->getResource().portSize;
    uint32_t addr = isa_device_desc->getResource().portBase;
    uint32_t irq = isa_device_desc->getResource().irq;

    std::stringstream ss;
    ss << dev->qdev.id << "-io";

    memory_region_init_io(&symb_isa_state->io, &symbhw_io_ops, symb_isa_state, ss.str().c_str(), size);

    hw->setSymbolicPortRange(addr, size, true);
    isa_init_irq(dev, &symb_isa_state->qirq, irq);
    isa_device_desc->assignIrq(&symb_isa_state->qirq);

    return 0;
}


static void isa_symbhw_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    ISADeviceClass *k = ISA_DEVICE_CLASS(klass);

    IsaDeviceDescriptor *isa_desc = static_cast<IsaDeviceDescriptor*>(data);

    k->init = isa_symbhw_init;

    dc->vmsd = isa_desc->getVmStateDescription();
    dc->props = isa_desc->getProperties();
}


}
}
