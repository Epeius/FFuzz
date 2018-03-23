///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <s2e/S2EExecutor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/SymbolicHardwareHook.h>
#include <klee/AddressSpace.h>
#include "UsbSymbolicDevice.h"
#include "SymbolicHardware.h"

#include <memory.h>

namespace s2e {
namespace plugins {

UsbDeviceDescriptor* UsbDeviceDescriptor::create(SymbolicHardware *plg, ConfigFile *cfg, const std::string &key)
{
    bool ok;
    llvm::raw_ostream &ws = plg->getWarningsStream();
    //llvm::raw_ostream &ms = plg->getInfoStream();

    std::string id = cfg->getString(key + ".id", "", &ok);
    if (!ok) {
        ws << "You must specify an id for the USB device in " << key << ".id\n";
        exit(-1);
    }

    UsbDeviceDescriptor *ret = new UsbDeviceDescriptor(id);

    ret->m_concreteDeviceActive = true;

    plg->s2e()->getCorePlugin()->onStateSwitch.connect(
       sigc::mem_fun(*ret, &UsbDeviceDescriptor::onStateSwitch)
    );

    return ret;
}

void UsbDeviceDescriptor::print(llvm::raw_ostream &os) const
{

}

void UsbDeviceDescriptor::initializeQemuDevice()
{

}

void UsbDeviceDescriptor::activateQemuDevice(void *bus)
{

}

void UsbDeviceDescriptor::onStateSwitch(S2EExecutionState *oldState, S2EExecutionState *newState)
{
    m_concreteDeviceActive = false;
}

}
}
