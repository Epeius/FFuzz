///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "s2e_qemu.h"
#include "SymbolicHardwareHook.h"

extern "C" {
    unsigned g_s2e_enable_mmio_checks = 0;
}

namespace s2e {

SymbolicPortHook g_symbolicPortHook;
SymbolicMemoryHook g_symbolicMemoryHook;

void SymbolicHardwareHookEnableMmioCallbacks(bool enable)
{
    g_s2e_enable_mmio_checks = enable;
}

}

int s2e_is_port_symbolic(uint64_t port)
{
    return s2e::g_symbolicPortHook.symbolic(port);
}

int se_is_mmio_symbolic(struct MemoryRegion *mr, uint64_t address, uint64_t size)
{
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, size);
}

int se_is_mmio_symbolic_b(struct MemoryRegion *mr, uint64_t address)
{
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 1);
}

int se_is_mmio_symbolic_w(struct MemoryRegion *mr, uint64_t address)
{
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 2);
}

int se_is_mmio_symbolic_l(struct MemoryRegion *mr, uint64_t address)
{
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 4);
}

int se_is_mmio_symbolic_q(struct MemoryRegion *mr, uint64_t address)
{
    return s2e::g_symbolicMemoryHook.symbolic(mr, address, 8);
}
