#ifndef WINDOWSMONITOR2_H

#define WINDOWSMONITOR2_H

#include "s2e.h"

/********************************************************/
/* WindowsMonitor2 stuff */
#define R_FS 4
#define R_GS 5

typedef enum S2E_WINMON2_COMMANDS {
    INIT_KERNEL_STRUCTS,
    LOAD_DRIVER,
    UNLOAD_DRIVER,
    THREAD_CREATE,
    THREAD_EXIT,
    LOAD_IMAGE,
    LOAD_PROCESS,
    UNLOAD_PROCESS,
    ACCESS_FAULT,
    PROCESS_HANDLE_CREATE,

    ALLOCATE_VIRTUAL_MEMORY,
    FREE_VIRTUAL_MEMORY,
    PROTECT_VIRTUAL_MEMORY,
    MAP_VIEW_OF_SECTION,
    UNMAP_VIEW_OF_SECTION,

    STORE_NORMALIZED_NAME
} S2E_WINMON2_COMMANDS;

typedef struct S2E_WINMON2_KERNEL_STRUCTS {
    UINT64 KernelNativeBase;
    UINT64 KernelLoadBase;
    UINT64 KernelChecksum;
    UINT64 KernelMajorVersion;
    UINT64 KernelMinorVersion;
    UINT64 KernelBuildNumber;

    UINT64 LoadDriverPc;
    UINT64 UnloadDriverPc;
    UINT64 LoadDriverHook;

    UINT64 PointerSizeInBytes;

    UINT64 KeBugCheckEx;
    UINT64 BugCheckHook;

    UINT64 KPCR;

    //The KPRCB is a struct at the end of the KPCR
    UINT64 KPRCB;
    UINT64 KdDebuggerDataBlock; //Address in the kernel file
    UINT64 KdVersionBlock; //Stored in the KPCR

    /**
     * Index of the segment that contains the pointer
     * to the current thread.
     */
    UINT64 EThreadSegment; //R_FS / RG_S
    UINT64 EThreadSegmentOffset;
    UINT64 EThreadStackBaseOffset;
    UINT64 EThreadStackLimitOffset;
    UINT64 EThreadProcessOffset;
    UINT64 EThreadCid;

    UINT64 EProcessUniqueIdOffset;
    UINT64 EProcessCommitChargeOffset;
    UINT64 EProcessVirtualSizeOffset;
    UINT64 EProcessPeakVirtualSizeOffset;
    UINT64 EProcessCommitChargePeakOffset;
    UINT64 EProcessVadRootOffset;

    UINT64 DPCStackBasePtr;
    UINT64 DPCStackSize;

    UINT64 PsLoadedModuleList;

    UINT64 PerfLogImageUnload;

    UINT64 KiRetireDpcCallSite;
} S2E_WINMON2_KERNEL_STRUCTS;

#define S2E_MODULE_MAX_LEN 255
typedef struct S2E_WINMON2_MODULE {
    UINT64 LoadBase;
    UINT64 Size;
    UINT64 FileNameOffset;
    UCHAR  FullPathName[S2E_MODULE_MAX_LEN + 1];
}S2E_WINMON2_MODULE;

typedef struct S2E_WINMON2_MODULE2 {
    UINT64 LoadBase;
    UINT64 Size;
    UINT64 Pid;
    UINT64 UnicodeModulePath;
    UINT64 UnicodeModulePathSizeInBytes;
}S2E_WINMON2_MODULE2;

typedef struct S2E_WINMON2_ACCESS_FAULT {
    UINT64 Address;
    UINT64 AccessMode;
    UINT64 StatusCode;
    UINT64 TrapInformation;
    UINT64 ReturnAddress;
} S2E_WINMON2_ACCESS_FAULT;

typedef struct S2E_WINMON2_PROCESS_CREATION {
    UINT64 ProcessId;
    UINT64 ParentProcessId;
    UINT64 EProcess;
    CHAR ImageFileName[16];
} S2E_WINMON2_PROCESS_CREATION;

typedef struct S2E_WINMON2_THREAD_CREATION {
    UINT64 ProcessId;
    UINT64 ThreadId;
    UINT64 EThread;
} S2E_WINMON2_THREAD_CREATION;

typedef struct S2E_WINMON2_PROCESS_HANDLE_CREATION {
    /* The process that requested the handle */
    UINT64 SourceProcessId;

    /* The process that the handle is referencing */
    UINT64 TargetProcessId;

    /* The handle itself */
    UINT64 Handle;
} S2E_WINMON2_PROCESS_HANDLE_CREATION;


typedef struct S2E_WINMON2_ALLOCATE_VM {
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 AllocationType;
    UINT64 Protection;
} S2E_WINMON2_ALLOCATE_VM;

typedef struct S2E_WINMON2_FREE_VM {
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 FreeType;
} S2E_WINMON2_FREE_VM;


typedef struct S2E_WINMON2_PROTECT_VM {
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 NewProtection;
    UINT64 OldProtection;
} S2E_WINMON2_PROTECT_VM;

typedef struct S2E_WINMON2_MAP_SECTION {
    UINT64 Status;
    UINT64 ProcessHandle;
    UINT64 BaseAddress;
    UINT64 Size;
    UINT64 AllocationType;
    UINT64 Win32Protect;
} S2E_WINMON2_MAP_SECTION;

typedef struct S2E_WINMON2_UNMAP_SECTION {
    UINT64 Status;
    UINT64 EProcess;
    UINT64 Pid;
    UINT64 BaseAddress;
} S2E_WINMON2_UNMAP_SECTION;

typedef struct S2E_WINMON2_NORMALIZED_NAME {
    UINT64 OriginalName;
    UINT64 OriginalNameSizeInBytes;
    UINT64 NormalizedName;
    UINT64 NormalizedNameSizeInBytes;
} S2E_WINMON2_NORMALIZED_NAME;

typedef struct S2E_WINMON2_COMMAND {
    S2E_WINMON2_COMMANDS Command;
    union {
        S2E_WINMON2_MODULE Module;
        S2E_WINMON2_MODULE2 Module2;
        S2E_WINMON2_KERNEL_STRUCTS Structs;
        S2E_WINMON2_ACCESS_FAULT AccessFault;
        S2E_WINMON2_THREAD_CREATION Thread;
        S2E_WINMON2_PROCESS_CREATION Process;
        S2E_WINMON2_PROCESS_HANDLE_CREATION ProcessHandle;

        S2E_WINMON2_ALLOCATE_VM AllocateVirtualMemory;
        S2E_WINMON2_FREE_VM FreeVirtualMemory;
        S2E_WINMON2_PROTECT_VM ProtectVirtualMemory;
        S2E_WINMON2_MAP_SECTION MapViewOfSection;
        S2E_WINMON2_UNMAP_SECTION UnmapViewOfSection;

        S2E_WINMON2_NORMALIZED_NAME NormalizedName;
    };
} S2E_WINMON2_COMMAND;

static VOID WinMon2SendNormalizedName(PUNICODE_STRING Original, PUNICODE_STRING Normalized)
{
    S2E_WINMON2_COMMAND Command;
    Command.Command = STORE_NORMALIZED_NAME;
    Command.NormalizedName.OriginalName = (UINT_PTR) Original->Buffer;
    Command.NormalizedName.OriginalNameSizeInBytes = (UINT_PTR) Original->Length;
    Command.NormalizedName.NormalizedName = (UINT_PTR) Normalized->Buffer;
    Command.NormalizedName.NormalizedNameSizeInBytes = (UINT_PTR) Normalized->Length;

    S2EInvokePlugin("WindowsMonitor2", &Command, sizeof(Command));
}


#endif