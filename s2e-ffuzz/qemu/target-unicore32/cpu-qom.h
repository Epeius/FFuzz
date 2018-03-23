/*
 * QEMU UniCore32 CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation, or (at your option) any
 * later version. See the COPYING file in the top-level directory.
 */
#ifndef QEMU_UC32_CPU_QOM_H
#define QEMU_UC32_CPU_QOM_H

#include "qemu/cpu.h"
#include "cpu.h"

#define TYPE_UNICORE32_CPU "unicore32-cpu"

#define UNICORE32_CPU_CLASS(klass) \
    OBJECT_CLASS_CHECK(UniCore32CPUClass, (klass), TYPE_UNICORE32_CPU)
#define UNICORE32_CPU(obj) \
    OBJECT_CHECK(UniCore32CPU, (obj), TYPE_UNICORE32_CPU)
#define UNICORE32_CPU_GET_CLASS(obj) \
    OBJECT_GET_CLASS(UniCore32CPUClass, (obj), TYPE_UNICORE32_CPU)

/**
 * UniCore32CPUClass:
 *
 * A UniCore32 CPU model.
 */
typedef struct UniCore32CPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/
} UniCore32CPUClass;

/**
 * UniCore32CPU:
 * @env: #CPUUniCore32State
 *
 * A UniCore32 CPU.
 */
typedef struct UniCore32CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUUniCore32State env;
} UniCore32CPU;

static inline UniCore32CPU *uc32_env_get_cpu(CPUUniCore32State *env)
{
    return UNICORE32_CPU(container_of(env, UniCore32CPU, env));
}

#define ENV_GET_CPU(e) CPU(uc32_env_get_cpu(e))


#endif
