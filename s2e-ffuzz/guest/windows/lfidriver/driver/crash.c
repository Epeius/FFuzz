#include <ntddk.h>
#include <Aux_klib.h>
#include "s2e.h"
#include "hook.h"
#include "crash.h"

#include <WindowsMonitor2.h>

static BOOLEAN BugCheckCallbackRegistered = FALSE;
static KBUGCHECK_REASON_CALLBACK_RECORD BugCheckRecord;
static PUCHAR LFI_DRIVER = (PUCHAR) "lfidriver"; //XXX: Ugly cast

#define CRASH_DUMP_HEADER_SIZE 0x2000
static UINT8 s_BugCheckHeaderBuffer[CRASH_DUMP_HEADER_SIZE];

extern S2E_WINMON2_KERNEL_STRUCTS g_KernelStructs;
extern LFIDRIVER_KERNEL_STRUCTS g_LfiKernelStructs;

UINT_PTR ToRuntimeAddress(UINT64 Address)
{
    return (UINT_PTR) (Address - (UINT_PTR) g_KernelStructs.KernelNativeBase
                   + (UINT_PTR) g_KernelStructs.KernelLoadBase);
}

/**
 * Windows 8 x64 encrypts the KdDebuggerDataBlock structure.
 * The variable KdpDataBlockEncoded indicates whether it is
 * encrypted or not. This routine calls the internal Windows
 * functions in order to decrypt the block before generating
 * the crash dump.
 */
VOID DecryptKdDataBlock()
{
    KdCopyDataBlock *Routine;
    PCHAR IsEncoded;

    if (!g_LfiKernelStructs.KdCopyDataBlock) {
        S2EMessage("KdCopyDataBlock is NULL\n");
        return;
    }

    IsEncoded = (PCHAR) (UINT_PTR) ToRuntimeAddress(g_LfiKernelStructs.KdpDataBlockEncoded);

    if (*IsEncoded) {
        Routine = (KdCopyDataBlock*) ToRuntimeAddress(g_LfiKernelStructs.KdCopyDataBlock);
        Routine((PVOID) ToRuntimeAddress(g_KernelStructs.KdDebuggerDataBlock));
        *IsEncoded = 0;
    }
}

/**
 * Dynamically loads the real KeInitializeCrashDumpHeader routine.
 * Allows the driver to work on WinXP.
 */
static NTSTATUS LfiKeInitializeCrashDumpHeader(
    ULONG DumpType,
    ULONG Flags,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BufferNeeded
    )
{
    #if _WIN32_WINNT >= _WIN32_WINNT_WS03
    return KeInitializeCrashDumpHeader(DumpType, Flags, Buffer, BufferSize, BufferNeeded);
    #else
    PVOID Address;
    UNICODE_STRING Str;
    static NTSTATUS (*_KeInitializeCrashDumpHeader)(ULONG DumpType, ULONG Flags, PVOID Buffer,
                                          ULONG BufferSize,PULONG BufferNeeded) = NULL;

    if (!_KeInitializeCrashDumpHeader) {
        RtlInitUnicodeString(&Str, L"KeInitializeCrashDumpHeader");
        _KeInitializeCrashDumpHeader = MmGetSystemRoutineAddress(&Str);
        if (!_KeInitializeCrashDumpHeader) {
            return STATUS_NOT_SUPPORTED;
        }
    }
    return _KeInitializeCrashDumpHeader(DumpType, Flags, Buffer, BufferSize, BufferNeeded);

    #endif
}

/**
 *  WindowsMonitor2 hooks the KeBugCheckEx function
 *  and redirects execution to here.
 *  This function initializes the bug check header and transmits it to S2E.
 */

NTSTATUS InitializeCrashDumpHeader(ULONG *BufferSize)
{
    NTSTATUS Status;
    ULONG BufferNeeded = 0;

    /* Determine the size for the buffer */
    Status = LfiKeInitializeCrashDumpHeader(
        1 /* DUMP_TYPE_FULL */, 0,
        s_BugCheckHeaderBuffer, 0, &BufferNeeded);

    if (BufferNeeded > 0) {
        S2EMessageFmt("S2EBSODHook: crash dump header of size %#x\n", BufferNeeded);

        if (BufferNeeded > CRASH_DUMP_HEADER_SIZE) {
            S2EMessageFmt("S2EBSODHook: required buffer too big");
            Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            Status = LfiKeInitializeCrashDumpHeader(
                1 /* DUMP_TYPE_FULL */, 0,
                s_BugCheckHeaderBuffer, BufferNeeded, NULL);

            if (!NT_SUCCESS(Status)) {
                S2EMessageFmt("S2EBSODHook: failed to initialize crash dump header\n");
            }
        }
    }

    *BufferSize = BufferNeeded;
    return Status;
}

NTSTATUS InitializeManualCrash(PVOID *Header, UINT64 *HeaderSize)
{
    ULONG BufferNeeded = 0;
    if (!Header || !HeaderSize) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeCrashDumpHeader(&BufferNeeded);

    #if _WIN32_WINNT >= _WIN32_WINNT_WIN8
    DecryptKdDataBlock();
    #endif

    KeSaveStateForHibernate(g_LfiKernelStructs.PRCBProcessorStateOffset);

    *Header = s_BugCheckHeaderBuffer;
    *HeaderSize = BufferNeeded;
    return STATUS_SUCCESS;
}

VOID S2EBSODHook(
    ULONG BugCheckCode,
    ULONG_PTR BugCheckParameter1,
    ULONG_PTR BugCheckParameter2,
    ULONG_PTR BugCheckParameter3,
    ULONG_PTR BugCheckParameter4
)
{
    NTSTATUS Status;
    S2E_BSOD_CRASH Command;
    ULONG BufferNeeded = 0;
    S2EMessage("lfidriver: invoked S2EBSODHook\n");
    InitializeCrashDumpHeader(&BufferNeeded);

    #if _WIN32_WINNT >= _WIN32_WINNT_WIN8
    DecryptKdDataBlock();
    #endif

    Command.Header = (UINT_PTR) s_BugCheckHeaderBuffer;
    Command.HeaderSize = BufferNeeded;
    Command.Code = BugCheckCode;
    Command.Parameters[0] = BugCheckParameter1;
    Command.Parameters[1] = BugCheckParameter2;
    Command.Parameters[2] = BugCheckParameter3;
    Command.Parameters[3] = BugCheckParameter4;

    S2EInvokePlugin("BlueScreenInterceptor", &Command, sizeof(Command));
    S2EKillState(0, "lfidriver: unreachable code in S2EBSODHook");
}

UINT_PTR GetS2ECrashHookAddress()
{
    RTL_OSVERSIONINFOW Version;
    Version.dwOSVersionInfoSize = sizeof(Version);
    RtlGetVersion(&Version);

    if (Version.dwMajorVersion == 0x5 && Version.dwMinorVersion == 0x1) {
        S2EMessage("lfidriver: no S2EBSODHook for this Windows version\n");
        return 0;
    }

    S2EMessageFmt("lfidriver: S2EBSODHook is at %p\n", S2EBSODHook);
    return (UINT_PTR) S2EBSODHook;
}


/*
Info about registering dump devices:
http://www.osronline.com/showThread.cfm?link=82275

typedef struct _DUMP_IRP{
    ULONG unknown1[3];
    PVOID Buffer; //0ch,
    PVOID Buffer1; //10h
    ULONG Length; //14h,
}DUMP_IRP, *PDUMP_IRP;

MMDUMP_FUNCTIONS_DESCRIPTOR

http://www.nosuchcon.org/talks/D3_01_Aaron_Crashdmpster_Diving_Win8.pdf

Hook crashdmp.sys to intercept write calls?
    Seems like the simplest thing to do.
Install a crash control dump filter?

Crash dump filter drivers

Some info about writing dumps
http://media.blackhat.com/bh-us-10/whitepapers/Suiche/BlackHat-USA-2010-Suiche-Blue-Screen-of-the-Death-is-dead-wp.pdf

http://computer.forensikblog.de/en/2008/02/64bit-crash-dumps.html

Interesting data structures
https://code.google.com/p/volatility/source/browse/branches/scudette/tools/windows/winpmem/kd.h?r=2686
_KDDEBUGGER_DATA64
http://computer.forensikblog.de/files/010_templates/DMP.bt

=> Seems to be possible to set the size of the crash dump at run time without rebooting

IopInitializeCrashDump
  - Read registry for config
    \Registry\Machine\System\CurrentControlSet\Control\CrashControl
      AutoReboot
      CrashDumpEnabled

  - IopLoadCrashdumpDriver
  - Allocate mem for CrashdmpDumpBlock
  - CrashdmpInitialized = 1
  Dumpfve.sys, Bitlocker Drive Encryption Crashdump Filter.
  diskdump.sys => used to write dumps to disk

http://www.slideshare.net/CrowdStrike/io-you-own-regaining-control-of-your-disk-in-the-presence-of-bootkits#btnNext

=> patch callback table in crash dump driver???
=> still need to make it work with page file disabled.

-> Disable page file


*/