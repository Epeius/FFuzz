#include <ntddk.h>
#include <Aux_klib.h>

#ifndef S2E_CRASH_H

#define S2E_CRASH_H

#if _WIN32_WINNT >= _WIN32_WINNT_WS03

NTSTATUS
  KeInitializeCrashDumpHeader(
    ULONG  DumpType,
    ULONG  Flags,
    PVOID  Buffer,
    ULONG  BufferSize,
    PULONG  BufferNeeded
    );

#endif

typedef NTSTATUS NTAPI KdCopyDataBlock(PVOID Buffer);

VOID DecryptKdDataBlock();
UINT_PTR GetS2ECrashHookAddress();
NTSTATUS InitializeCrashDumpHeader(ULONG *BufferSize);
NTSTATUS InitializeManualCrash(PVOID *Header, UINT64 *HeaderSize);

/* PKPROCESSOR_STATE State */
VOID __cdecl KeSaveStateForHibernate(PVOID State);

#endif