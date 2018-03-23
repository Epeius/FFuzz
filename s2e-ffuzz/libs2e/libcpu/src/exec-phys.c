/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven, Inc
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#include <inttypes.h>
#include <cpu/config.h>
#include "qemu-common.h"
#include "osdep.h"
#include <cpu/memory.h>
#include "exec.h"



const uint16_t phys_section_unassigned = 0;
const uint16_t phys_section_notdirty = 1;
const uint16_t phys_section_rom = 2;
const uint16_t phys_section_watch = 3;

static const uint64_t phys_section_max_dummy = 4;

static struct MemoryDescOps s_memops[phys_section_max_dummy];


////////////////////////////////////////////////////////////////////////////////////////
/// Public functions

void phys_register_section(unsigned index, const struct MemoryDescOps *ops)
{
    assert(index < phys_section_max_dummy);
    s_memops[index] = *ops;
}

const struct MemoryDescOps *phys_get_ops(target_phys_addr_t index)
{
    unsigned idx = index & ~TARGET_PAGE_MASK;
    assert(idx < phys_section_max_dummy);
    return &s_memops[idx];
}

const MemoryDesc *phys_page_find(target_phys_addr_t index)
{
    return mem_desc_find(index << TARGET_PAGE_BITS);
}



#ifdef CONFIG_SYMBEX
void se_phys_section_print(void)
{
    assert(false && "Not implemented");

#if 0
    g_sqi.log.debug("Dumping memory sections\n");
    for (unsigned i = 0; i < phys_sections_nb; ++i) {
        const MemoryRegionSection *section = &phys_sections[i];
        g_sqi.log.debug("Section %d: addr=%x size=%x name=%s\n", i,
                        section->offset_within_address_space, section->size, section->mr->name);
    }
#endif
}

void se_phys_section_check(CPUArchState *cpu_state)
{
    assert(false && "Not implemented");
#if 0
    for (unsigned i = 0; i < NB_MMU_MODES; i++) {
        for (unsigned j = 0; j < CPU_TLB_SIZE; j++) {
            target_phys_addr_t physaddr = cpu_state->iotlb[i][j];
            unsigned index = physaddr & ~TARGET_PAGE_MASK;

            if (index < phys_section_max_dummy) {
                //Dummy sections for physical memory are always created first
                //in the same order, they are not affected by layout changes.
                continue;
            }

            //XXX: how to deal with large pages? Is it necessary?
            if (index >= phys_sections_nb) {
                se_flush_tlb_cache_page(cpu_state->tlb_table[i][j].objectState, i, j);
                cpu_state->tlb_table[i][j] = s_cputlb_empty_entry;
            } else {
                target_phys_addr_t off = phys_sections[index].offset_within_address_space;
                if (off != cpu_state->iotlb_ramaddr[i][j]) {
                    se_flush_tlb_cache_page(cpu_state->tlb_table[i][j].objectState, i, j);
                    cpu_state->tlb_table[i][j] = s_cputlb_empty_entry;
                }
            }
        }
    }
#endif
}

#endif

