#ifndef S2E_STATIC_STATE_MERGER

#define S2E_STATIC_STATE_MERGER

#include "s2e.h"

static VOID S2ERegisterMergeCallback()
{
    UINT64 Cb = (UINT_PTR) S2EMergePointCallback;
    S2EInvokePlugin("StaticStateMerger", &Cb, sizeof(Cb));
}

#endif
