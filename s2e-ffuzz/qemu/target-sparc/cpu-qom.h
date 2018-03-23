/*
 * QEMU SPARC CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */
#ifndef QEMU_SPARC_CPU_QOM_H
#define QEMU_SPARC_CPU_QOM_H

#include "qemu/cpu.h"
#include "cpu.h"

#ifdef TARGET_SPARC64
#define TYPE_SPARC_CPU "sparc64-cpu"
#else
#define TYPE_SPARC_CPU "sparc-cpu"
#endif

#define SPARC_CPU_CLASS(klass) \
    OBJECT_CLASS_CHECK(SPARCCPUClass, (klass), TYPE_SPARC_CPU)
#define SPARC_CPU(obj) \
    OBJECT_CHECK(SPARCCPU, (obj), TYPE_SPARC_CPU)
#define SPARC_CPU_GET_CLASS(obj) \
    OBJECT_GET_CLASS(SPARCCPUClass, (obj), TYPE_SPARC_CPU)

/**
 * SPARCCPUClass:
 * @parent_reset: The parent class' reset handler.
 *
 * A SPARC CPU model.
 */
typedef struct SPARCCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    void (*parent_reset)(CPUState *cpu);
} SPARCCPUClass;

/**
 * SPARCCPU:
 * @env: #CPUSPARCState
 *
 * A SPARC CPU.
 */
typedef struct SPARCCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUSPARCState env;
} SPARCCPU;

static inline SPARCCPU *sparc_env_get_cpu(CPUSPARCState *env)
{
    return SPARC_CPU(container_of(env, SPARCCPU, env));
}

#define ENV_GET_CPU(e) CPU(sparc_env_get_cpu(e))


#endif
