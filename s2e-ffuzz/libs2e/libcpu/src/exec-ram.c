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


#include <cpu/config.h>
#include "qemu-common.h"
#include "osdep.h"
#include "exec.h"
#include "exec-ram.h"

RAMList ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };

void *get_ram_list_phys_dirty(void)
{
    return ram_list.phys_dirty;
}

static ram_addr_t find_ram_offset(ram_addr_t size)
{
    RAMBlock *block, *next_block;
    ram_addr_t offset = RAM_ADDR_MAX, mingap = RAM_ADDR_MAX;

    if (QLIST_EMPTY(&ram_list.blocks))
        return 0;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        ram_addr_t end, next = RAM_ADDR_MAX;

        end = block->offset + block->length;

        QLIST_FOREACH(next_block, &ram_list.blocks, next) {
            if (next_block->offset >= end) {
                next = MIN(next, next_block->offset);
            }
        }
        if (next - end >= size && next - end < mingap) {
            offset = end;
            mingap = next - end;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        fprintf(stderr, "Failed to find gap of requested size: %" PRIu64 "\n",
                (uint64_t)size);
        abort();
    }

    return offset;
}

ram_addr_t last_ram_offset(void)
{
    RAMBlock *block;
    ram_addr_t last = 0;

    QLIST_FOREACH(block, &ram_list.blocks, next)
        last = MAX(last, block->offset + block->length);

    return last;
}


ram_addr_t qemu_ram_alloc_from_ptr(ram_addr_t size, void *host)
{
    RAMBlock *new_block;
    assert(host);

    size = TARGET_PAGE_ALIGN(size);
    new_block = g_malloc0(sizeof(*new_block));

    new_block->offset = find_ram_offset(size);

    new_block->host = host;
    new_block->flags |= RAM_PREALLOC_MASK;

    new_block->length = size;

    QLIST_INSERT_HEAD(&ram_list.blocks, new_block, next);

    ram_list.phys_dirty = g_realloc(ram_list.phys_dirty,
                                       last_ram_offset() >> TARGET_PAGE_BITS);
    memset(ram_list.phys_dirty + (new_block->offset >> TARGET_PAGE_BITS),
           0xff, size >> TARGET_PAGE_BITS);

    return new_block->offset;
}


void qemu_ram_free_from_ptr(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr == block->offset) {
            QLIST_REMOVE(block, next);
            g_free(block);
            return;
        }
    }
}

/* Return a host pointer to ram allocated with qemu_ram_alloc.
   With the exception of the softmmu code in this file, this should
   only be used for local memory (e.g. video ram) that the device owns,
   and knows it isn't going to access beyond the end of the block.

   It should not be used for general purpose DMA.
   Use cpu_physical_memory_map/cpu_physical_memory_rw instead.
 */
void *qemu_get_ram_ptr(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->length) {
            /* Move this entry to to start of the list.  */
            if (block != QLIST_FIRST(&ram_list.blocks)) {
                QLIST_REMOVE(block, next);
                QLIST_INSERT_HEAD(&ram_list.blocks, block, next);
            }
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

    return NULL;
}


/* Return a host pointer to ram allocated with qemu_ram_alloc.
 * Same as qemu_get_ram_ptr but avoid reordering ramblocks.
 */
void *qemu_safe_ram_ptr(ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->length) {
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

    return NULL;
}

/* Return a host pointer to guest's ram. Similar to qemu_get_ram_ptr
 * but takes a size argument */
void *qemu_ram_ptr_length(ram_addr_t addr, ram_addr_t *size)
{
    if (*size == 0) {
        return NULL;
    }
    RAMBlock *block;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        if (addr - block->offset < block->length) {
            if (addr - block->offset + *size > block->length)
                *size = block->length - addr + block->offset;
            return block->host + (addr - block->offset);
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();
}

void qemu_put_ram_ptr(void *addr)
{
    //trace_qemu_put_ram_ptr(addr);
}

int qemu_ram_addr_from_host(void *ptr, ram_addr_t *ram_addr)
{
    RAMBlock *block;
    uint8_t *host = ptr;

    QLIST_FOREACH(block, &ram_list.blocks, next) {
        /* This case append when the block is not mapped. */
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->length) {
            *ram_addr = block->offset + (host - block->host);
            return 0;
        }
    }

    return -1;
}

/* Some of the softmmu routines need to translate from a host pointer
   (typically a TLB entry) back to a ram offset.  */
ram_addr_t qemu_ram_addr_from_host_nofail(void *ptr)
{
    ram_addr_t ram_addr;

    if (qemu_ram_addr_from_host(ptr, &ram_addr)) {
        fprintf(stderr, "Bad ram pointer %p\n", ptr);
        abort();
    }
    return ram_addr;
}
