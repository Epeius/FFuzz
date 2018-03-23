/*
 * Copyright (c) 2015, CodeTickler
 * All rights reserved.
 *
 * Proprietary and confidential
 */

#ifndef __REVGEN_RUNTIME_H__

#define __REVGEN_RUNTIME_H__

#include <inttypes.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t (*revgen_function_t) ();

uint64_t revgen_entrypoint ();

extern uint64_t revgen_function_count;
extern revgen_function_t *revgen_function_pointers;
extern uint64_t *revgen_function_addresses;

int __detect_library_functions(int argc, char **argv);
extern int __revgen_detect_library_functions;

static inline void dosegfault(void) {
    volatile char *v = NULL;
    *v = 0;
}

void __revgen_validate_pointer(uint64_t pointer);

#ifdef __cplusplus
}
#endif

#endif
