///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef S2E_CONFIG_H
#define S2E_CONFIG_H


/** How many S2E instances we want to handle.
    Plugins can use this constant to allocate blocks of shared memory whose size
    depends on the maximum number of processes (e.g., bitmaps) */
#define S2E_MAX_PROCESSES 48

#define S2E_USE_FAST_SIGNALS

#define S2E_MEMCACHE_SUPERPAGE_BITS 20

#define S2E_RAM_SUBOBJECT_BITS 7
#define S2E_RAM_SUBOBJECT_SIZE (1 << S2E_RAM_SUBOBJECT_BITS)

#ifdef CONFIG_LIBS2E
#include <cpu/se_qemu_config.h>
#else

/** Enables S2E TLB to speed-up concrete memory accesses */
#define SE_ENABLE_TLB

/** This defines the size of each MemoryObject that represents physical RAM.
    Larger values save some memory, smaller (exponentially) decrease solving
    time for constraints with symbolic addresses */

#ifdef SE_ENABLE_TLB
//XXX: Use TARGET_PAGE_BITS somehow...
#define SE_RAM_OBJECT_BITS 12
#else
/* Do not touch this */
#define SE_RAM_OBJECT_BITS TARGET_PAGE_BITS
#endif

/** Force page sizes to be the native size. S2E performs dynamic page splitting
    in case of symbolic addresses, so there is no need to tweak this value anymore. */
#if SE_RAM_OBJECT_BITS != 12 || !defined(SE_ENABLE_TLB)
#error Incorrect TLB configuration
#endif

#define SE_RAM_OBJECT_SIZE (1 << SE_RAM_OBJECT_BITS)
#define SE_RAM_OBJECT_MASK (~(SE_RAM_OBJECT_SIZE - 1))

/** Enables simple memory debugging support */
//#define S2E_DEBUG_MEMORY
//#define S2E_DEBUG_TLBCACHE

#define S2E_MEMCACHE_SUPERPAGE_BITS 20

/** Whether to compile softmmu with memory tracing enabled. */
/** Can be disabled for debugging purposes. */
#if !defined(STATIC_TRANSLATOR)
#define SE_ENABLE_MEM_TRACING
#define TCG_ENABLE_MEM_TRACING
#endif

#ifdef CONFIG_SYMBEX_MP
#define SE_ENABLE_PHYSRAM_TLB
#endif

//#define SE_ENABLE_FAST_DIRTYMASK

/**
 * Use retranslation when recomputing the precise pc for
 * blocks that are not instrumented. Reduces the use of
 * expensive metadata.
 */
#define SE_ENABLE_RETRANSLATION

/** When enabled, the program counter is explicitely updated
  * between each guest instruction and compared to the
  * program counter recovered by cpu_restore_state. */
//#define S2E_ENABLE_PRECISE_EXCEPTION_DEBUGGING
//#define S2E_ENABLE_PRECISE_EXCEPTION_DEBUGGING_COMPARE

/**
 * Keep micro-operations in the translation cache.
 * QEMU normally discards them after generating machine code.
 */
//#define TCG_KEEP_OPC
#endif

#endif // S2E_CONFIG_H
