/**
 *
 * Copyright (c) 2016, CodeTickler
 * Proprietary and Confidential
 *
 */

#ifndef _S2E_SEED_H_

#define _S2E_SEED_H_

#include <s2e.h>
#include <inttypes.h>

typedef enum S2E_SEEDSEARCHER_COMMANDS {
    GET_SEED_FILE,
    ENABLE_SEARCHER,
    SEED_DONE
} S2E_SEEDSEARCHER_COMMANDS;

typedef struct S2E_SEEDSEARCHER_GETFILE
{
    /* Pointer to guest memory where the plugin will store the file name */
    uint64_t FileName;

    /* Size of the buffer in bytes, including null character */
    uint64_t FileNameSizeInBytes;

    /* 1 on success, 0 on failure (no seed file available) */
    uint64_t Result;
} __attribute__((packed)) S2E_SEEDSEARCHER_GETFILE;

typedef struct S2E_SEEDSEARCHER_COMMAND {
    S2E_SEEDSEARCHER_COMMANDS Command;
    union {
        S2E_SEEDSEARCHER_GETFILE GetFile;
    };
} __attribute__((packed)) S2E_SEEDSEARCHER_COMMAND;



static int s2e_seed_get_file(char *file, size_t bytes, int *should_fork)
{
    S2E_SEEDSEARCHER_COMMAND cmd;
    cmd.Command = GET_SEED_FILE;
    cmd.GetFile.FileName = (uintptr_t) file;
    cmd.GetFile.FileNameSizeInBytes = bytes;
    cmd.GetFile.Result = 0;

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    s2e_invoke_plugin("SeedSearcher", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();

    int ret = 0;
    switch (cmd.GetFile.Result) {
        /* No seed file, other states exploring, no need to fork */
        case 0: ret = -1; *should_fork = 0; break;

        /* No seed file, start exploration without seeds */
        case 1: ret = -1; *should_fork = 1; break;

        /* Seed file available, start exploring it */
        case 2: ret = 0; *should_fork = 1; break;
    }

    return ret;
}

static void s2e_seed_searcher_enable(void)
{
    S2E_SEEDSEARCHER_COMMAND cmd;
    cmd.Command = ENABLE_SEARCHER;

    s2e_begin_atomic();
    s2e_disable_all_apic_interrupts();
    s2e_invoke_plugin("SeedSearcher", &cmd, sizeof(cmd));
    s2e_enable_all_apic_interrupts();
    s2e_end_atomic();
}


#endif
