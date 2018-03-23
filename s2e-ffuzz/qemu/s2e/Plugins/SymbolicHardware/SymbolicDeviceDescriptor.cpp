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
#include "qemu/object.h"
#include "hw/qdev.h"
}

#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "SymbolicHardware.h"
#include "SymbolicDeviceDescriptor.h"
#include "PciSymbolicDevice.h"
#include "IsaSymbolicDevice.h"
#include "VfioSymbolicDevice.h"
#include "UsbSymbolicDevice.h"

namespace s2e {
namespace plugins {

DeviceDescriptor::DeviceDescriptor(const std::string &id)
{
   m_id = id;
   m_qemuIrq = NULL;
   m_qemuDev = NULL;

   m_devInfo = NULL;
   m_devInfoProperties = NULL;
   m_vmState = NULL;
   m_vmStateFields = NULL;
}

DeviceDescriptor::~DeviceDescriptor()
{
    if (m_devInfo)
        delete m_devInfo;

    if (m_devInfoProperties)
        delete [] m_devInfoProperties;

    if (m_vmState)
        delete m_vmState;

    if (m_vmStateFields)
        delete [] m_vmStateFields;
}

DeviceDescriptor *DeviceDescriptor::create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key)
{
    bool ok;
    llvm::raw_ostream &ws = plg->getWarningsStream();

    std::string id = cfg->getString(key + ".id", "", &ok);
    if (!ok || id.empty()) {
        ws << "You must specify an id for " << key << ". " <<
                "This is required by QEMU for saving/restoring snapshots." << '\n';
        return NULL;
    }

    //Check the type of device we want to create
    std::string devType = cfg->getString(key + ".type", "", &ok);
    if (!ok) {
        ws << "You must define a symbolic device!" << '\n';
        return NULL;
    }

    DeviceDescriptor *ret = NULL;
    if (devType == "isa") {
        ret = IsaDeviceDescriptor::create(plg, cfg, key);
    } else if (devType == "pci") {
        ret = PciDeviceDescriptor::create(plg, cfg, key);
    } else if (devType == "vfio") {
        ret = VfioDeviceDescriptor::create(plg, cfg, key);
    } else if (devType == "usb") {
        ret = UsbDeviceDescriptor::create(plg, cfg, key);
    } else {
        ws << devType << " is not a valid type of symbolic hardware\n";
        return NULL;
    }

    if (ret) {
        //XXX: Hotplug not supported for now.
        //Each state needs to hold different device configurations,
        //which QEMU cannot handle.
        //ret->m_pluggedIn = cfg->getBool(key + ".pluggedIn", true, &ok);
        ret->m_pluggedIn = true;
    }

    return ret;
}

}
}
