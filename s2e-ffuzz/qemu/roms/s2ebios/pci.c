/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include <s2e.h>
#include "pci.h"

uint32_t pci_find_device(uint16_t vid, uint16_t pid, uint8_t *b, uint8_t *d, uint8_t *f)
{
    for (uint8_t bus = 0; bus < 10; ++bus) {
        for (uint16_t device = 0; device < 256; ++device) {
            for (uint8_t function = 0; function < 8; ++function) {
                uint16_t fvid = pci_read_word(bus, device, function, 0);
                uint16_t fpid = pci_read_word(bus, device, function, 2);
                if (vid == fvid && pid == fpid) {
                    *b = bus;
                    *d = device;
                    *f = function;
                    return 1;
                }
                break;
            }
        }
    }
    return 0;
}

static uint64_t pci_get_bar_size(uint8_t bus, uint8_t device, uint8_t function, unsigned num, int *is_io, int *is64)
{
    uint32_t offset = PCI_BASE_ADDRESS_0 + sizeof(uint32_t) * num;
    uint32_t orig_bar = pci_read_dword(bus, device, function, offset);
    s2e_print_expression("pci_get_bar_size: orig_bar", orig_bar);

    pci_write_dword(bus, device, function, offset, ~0);
    uint64_t size = pci_read_dword(bus, device, function, offset);

    *is64 = 0;

    if (orig_bar & PCI_BASE_ADDRESS_SPACE_IO) {
        size &= ~0x3;
        size = size & ~(size-1);
        if (is_io)
            *is_io = 1;
    } else {

        if (orig_bar & PCI_BASE_ADDRESS_MEM_TYPE_64) {
            uint32_t offset_high = offset + sizeof(uint32_t);
            uint32_t orig_bar_high = pci_read_dword(bus, device, function, offset_high);
            pci_write_dword(bus, device, function, offset + sizeof(uint32_t), ~0);

            uint64_t size_high = pci_read_dword(bus, device, function, offset_high);
            size |= (size_high << 32);

            pci_write_dword(bus, device, function, offset_high, orig_bar_high);
        }

        size &= ~0xf;
        size = size & ~(size-1);
        if (is_io)
            *is_io = 0;
    }

    pci_write_dword(bus, device, function, offset, orig_bar);
    return size;
}

static uint64_t pci_get_bar_address(uint8_t bus, uint8_t device, uint8_t function, unsigned num, int *is_io, int *is64)
{
    uint32_t offset = PCI_BASE_ADDRESS_0 + sizeof(uint32_t) * num;
    uint64_t addr = pci_read_dword(bus, device, function, offset);

    *is64 = 0;
    if (addr & PCI_BASE_ADDRESS_SPACE_IO) {
        *is_io = 1;
        return addr & ~3;
    } else {

        if (addr & PCI_BASE_ADDRESS_MEM_TYPE_64) {
            uint32_t offset_high = offset + sizeof(uint32_t);
            uint64_t addr_high = pci_read_dword(bus, device, function, offset_high);
            addr |= (addr_high << 32);
            *is64 = 1;
        }

        *is_io = 0;
        return addr & ~0xf;
    }
}

void pci_set_bar_address(uint8_t bus, uint8_t device, uint8_t function, unsigned num, uint64_t address)
{
    uint32_t offset = PCI_BASE_ADDRESS_0 + sizeof(uint32_t) * num;
    uint32_t type = pci_read_dword(bus, device, function, offset);

    s2e_print_expression("pci_set_bar_address address", address);

    pci_write_dword(bus, device, function, offset, address & 0xffffffff);
    if (!(type & PCI_BASE_ADDRESS_SPACE_IO) && (type & PCI_BASE_ADDRESS_MEM_TYPE_64)) {
        pci_write_dword(bus, device, function, offset + sizeof(uint32_t), address >> 32);
    }

    int is_io, is64;
    uint64_t new_address = pci_get_bar_address(bus, device, function, num, &is_io, &is64);
    s2e_print_expression("pci_set_bar_address new_address", new_address);
    s2e_assert(new_address == address);
}

void pci_activate_io(uint8_t bus, uint8_t device, uint8_t function, int io, int mmio)
{
    uint16_t command = pci_read_word(bus, device, function, 0x4);

    int flags = 0;
    if (io) {
        flags |= 1;
    }

    if (mmio) {
        flags |= 2;
    }

    pci_write_word(bus, device, function, 0x4, command | flags); //Enable address space
    uint16_t new_command = pci_read_word(bus, device, function, 0x4);
    s2e_assert(new_command == (command | flags));
}

barinfo_t pci_get_bar_info(uint8_t bus, uint8_t device, uint8_t function, unsigned num)
{
    barinfo_t ret;
    ret.size = pci_get_bar_size(bus, device, function, num, &ret.isIo, &ret.is64);
    ret.address = 0;
    if (ret.size > 0) {
        ret.address = pci_get_bar_address(bus, device, function, num, &ret.isIo, &ret.is64);
    }

    s2e_print_expression("pci_get_bar_info: is64", ret.is64);
    s2e_print_expression("pci_get_bar_info: isIo", ret.isIo);
    s2e_print_expression("pci_get_bar_info: address", ret.address);
    s2e_print_expression("pci_get_bar_info: size", ret.size);

    return ret;
}
