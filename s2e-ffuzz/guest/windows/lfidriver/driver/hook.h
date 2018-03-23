#ifndef S2E_HOOK_H
#pragma warning(disable:4201)

#define S2E_HOOK_H

#include <WindowsDriverExerciser2.h>
#include <GuestCodePatching.h>


/********************************************************/
/* Communicating with the BugCollector plugin */

typedef struct _S2E_BUG_CUSTOM {
    UINT64 CustomCode;
    UINT64 DescriptionStr;
} S2E_BUG_CUSTOM;

typedef struct _S2E_BUG_WINDOWS_USERMODE_BUG {
    UINT64 ProgramName;
    UINT64 Pid;
    UINT64 ExceptionCode;
    UINT64 ExceptionAddress;
    UINT64 ExceptionFlags;
} S2E_BUG_WINDOWS_USERMODE_BUG;

typedef enum _S2E_BUG_COMMANDS {
    CUSTOM_BUG, WINDOWS_USERMODE_BUG
} S2E_BUG_COMMANDS;

typedef struct _S2E_BUG_CRASH_OPAQUE {
    UINT64 CrashOpaque;
    UINT64 CrashOpaqueSize;
} S2E_BUG_CRASH_OPAQUE;

typedef struct _S2E_BUG_COMMAND {
    S2E_BUG_COMMANDS Command;
    union {
        S2E_BUG_CUSTOM CustomBug;
        S2E_BUG_WINDOWS_USERMODE_BUG WindowsUserModeBug;
    };
    /* Optional, used by the crash dump plugin. */
    S2E_BUG_CRASH_OPAQUE CrashOpaque;
}S2E_BUG_COMMAND;

/********************************************************/

/* BlueScreenInterceptor */
typedef struct S2E_BSOD_CRASH {
    UINT64 Code;
    UINT64 Parameters[4];
    UINT64 Header;
    UINT64 HeaderSize;
}S2E_BSOD_CRASH;

/********************************************************/

typedef struct LFIDRIVER_KERNEL_STRUCTS {
    /**
     * Address of the Kernel debugger data block
     * decryption routine.
     */
    UINT64 KdCopyDataBlock;

    /**
     * Pointer to the kernel variable that stores
     * the encryption status of the the kernel
     * debugger data block.
     */
    UINT64 KdpDataBlockEncoded;

    PVOID PRCBProcessorStateOffset;

    /**
     * Watch for the termination of the process
     * specified by this pid.
     */
    DWORD WatchPid;

    PLIST_ENTRY PsActiveProcessHead;
    UINT64 EProcessActiveProcessLinkOffset;
    UINT64 EProcessThreadListHeadOffset;
    UINT64 EThreadThreadListEntry;

    UINT64 ObpCreateHandle;
    UINT64 MmAccessFault;
    UINT64 NtAllocateVirtualMemory;
    UINT64 NtFreeVirtualMemory;
    UINT64 NtProtectVirtualMemory;
    UINT64 NtMapViewOfSection;
    UINT64 NtUnmapViewOfSectionEx;
    UINT64 NtUnmapViewOfSection;
    UINT64 MiUnmapViewOfSection;
} LFIDRIVER_KERNEL_STRUCTS;


/********************************************************/

extern const S2E_HOOK g_NdisMiniportHooks[];
extern const S2E_HOOK g_NdisProtocolHooks[];
extern const S2E_HOOK g_NtoskrnlHooks[];

extern const S2E_HOOK g_Ndis60MiniportHooks[];

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

#if !defined(USER_APP)
VOID ReloadImports(PDRIVER_OBJECT DriverObject);
VOID ReloadModuleImports(PDRIVER_OBJECT DriverObject, PCSTR DriverName);

VOID InitializeWindowsMonitor2();
UINT_PTR GetS2ECrashHookAddress();

VOID S2ERegisterMergeCallback();
VOID S2ERegisterMainEntryPointHook(VOID);
VOID S2ERegisterReturnHook64(VOID);
VOID InitializeKernelHooks(VOID);

#endif

#endif
