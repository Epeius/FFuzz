/// Copyright (C) 2003  Fabrice Bellard
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

/* Common header file that is included by all of qemu.  */
#ifndef QEMU_COMMON_H
#define QEMU_COMMON_H

#include <qemu-compiler.h>
#include "config-host.h"


/* we put basic includes here to avoid repeating them in device drivers */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <assert.h>
#include <signal.h>
#include <glib.h>


/* FIXME: Remove NEED_CPU_H.  */
#ifndef NEED_CPU_H

#include "osdep.h"
#include "bswap.h"

#else

#include "cpu.h"

#endif /* !defined(NEED_CPU_H) */



bool tcg_enabled(void);


void qemu_init_vcpu(void *env);


#endif
