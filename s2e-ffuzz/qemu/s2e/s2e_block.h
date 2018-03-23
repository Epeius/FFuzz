///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef _S2E_BLOCK_H_

#define _S2E_BLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct BlockDriverState;

typedef int (*s2e_raw_read)(struct BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors);

/* Disk-related copy on write */
int s2e_bdrv_read(struct BlockDriverState *bs, int64_t sector_num,
                  uint8_t *buf, int nb_sectors);

int s2e_bdrv_write(struct BlockDriverState *bs, int64_t sector_num,
                   const uint8_t *buf, int nb_sectors);


extern int (*__hook_bdrv_read)(
                  struct BlockDriverState *bs, int64_t sector_num,
                  uint8_t *buf, int nb_sectors);

extern int (*__hook_bdrv_write)(
                   struct BlockDriverState *bs, int64_t sector_num,
                   const uint8_t *buf, int nb_sectors);


void s2e_bdrv_fail();

extern struct S2EExecutionState **g_block_s2e_state;

#ifdef __cplusplus
}
#endif

#endif
