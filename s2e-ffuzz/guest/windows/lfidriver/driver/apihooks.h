#ifndef __LFIDRIVER_API_HOOKS__

#define __LFIDRIVER_API_HOOKS__

#define REGISTER_NDIS_ENTRYPOINT(handle, struc, name) \
    if (struc->name) { \
        S2ERegisterDriverEntryPoint((UINT64) handle, #name, struc->name, NULL);\
    }

#define REGISTER_NDIS_ENTRYPOINT_HOOK(handle, struc, name) \
if (struc->name) { \
    S2ERegisterDriverEntryPoint((UINT64) handle, #name, struc->name, S2EHook_ndis_ ## name);\
}

#define REGISTER_NDIS_LIBRARY_HOOK(caller, handle, struc, name) \
if (struc->name) { \
    S2ERegisterExternalFunctionHook((UINT64) handle, #name, caller, struc->name, S2EHook_ndis_ ## name);\
}

#endif