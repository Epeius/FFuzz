///
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#include <stdio.h>

#include <cpu/exec.h>
#include <tcg/tcg.h>

int main()
{
    cpu_gen_init();
    tcg_prologue_init(&tcg_ctx);

    return 0;
}
