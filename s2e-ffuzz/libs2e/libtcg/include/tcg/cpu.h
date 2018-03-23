#ifndef __TCG_CPU_H__

#define __TCG_CPU_H__

#include <inttypes.h>

#ifdef CONFIG_SYMBEX
typedef struct tb_precise_pc_t_ {
    uint16_t host_pc_increment; //Increment from the start host pc of the tb
    uint16_t guest_pc_increment; //Increment from the start pc of the tb
    uint16_t opc;
    uint8_t cc_op;
    uint8_t guest_inst_size;
} tb_precise_pc_t;
#endif

#endif
