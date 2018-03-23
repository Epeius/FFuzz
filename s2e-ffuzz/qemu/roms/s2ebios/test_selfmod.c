#include <s2e.h>
#include "string.h"
#include "inttypes.h"
#include "main.h"

/**
 *  Tests self-modifying code
 *
 *  Inputs: RDX=0x5b07e8d8c90406de
 *          RCX=start of buffer
 *  0x2e, 0x48, 0x31, 0x11, 0x90, 0xd9, 0x56, 0x53
 *  00000000  2E483111          xor [cs:rcx],rdx
 *  00000004  90                nop
 *  00000005  D95653            fst dword [rsi+0x53]
 *  ...
 *
 *  TODO: put assertions
 */
void test_selfmod1()
{
    char code[] = {
        0x2e, 0x48, 0x31, 0x11, 0x90, 0xd9, 0x56, 0x53,
        0x96, 0x37, 0x55, 0xd9, 0x90, 0xd9, 0x56, 0x43,
        0x96, 0x37, 0x55, 0xe9, 0x90, 0xd9, 0x56, 0x73
    };

    void *exec_mem = (char *) 0x301bd;

    memset(exec_mem, 0xf4, 0x1000); //Put hlt everywhere
    memcpy(exec_mem, code, sizeof(code));

    #ifdef __x86_64__
    __asm__ __volatile__(
        "mov %0, %%rax\n"
        "mov %%rax, %%rcx\n"
        "mov $0x5b07e8d8c90406de, %%rdx\n"
        "callq *%%rax\n"::"a"(exec_mem)
    );

    #else
    s2e_message("test_selfmod1 not supported in 32-bits mode");
    #endif
}
