#pragma warning(disable:4706) //assignment within conditional expression

#define USER_APP

#include <stdio.h>
#include <windows.h>

#include <winioctl.h>
#include <lfictl.h>

#include <s2e.h>
#include <hook.h>
#include "testctl.h"
#include "TlHelp32.h"

static DWORD GetParentPid(VOID)
{
    HANDLE Snapshot;
    BOOL Result;
    DWORD RetVal = 0;
    DWORD CurrentPid = GetCurrentProcessId();
    PROCESSENTRY32 ProcessEntry;

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) {
        const char *err = GetErrorString(GetLastError());
        S2EMessageFmt("GetParentPid() failed: %s\n", err);
        goto err1;
    }

    ProcessEntry.dwSize = sizeof(ProcessEntry);
    Result = Process32First(Snapshot, &ProcessEntry);

    do {
        if (!Result) {
            const char *err = GetErrorString(GetLastError());
            S2EMessageFmt("Process32First() failed: %s\n", err);
            goto err2;
        }

        if (ProcessEntry.th32ProcessID == CurrentPid) {
            RetVal = ProcessEntry.th32ParentProcessID;
        }

    } while (Result = Process32Next(Snapshot, &ProcessEntry));

    err2: CloseHandle(Snapshot);
    err1: return RetVal;
}

BOOL RegisterWatchdog(VOID)
{
    HANDLE Handle;
    DWORD ParentPid = GetParentPid();
    if (!ParentPid) {
        S2EMessageFmt("Could not find parent process ID to monitor\n");
        return FALSE;
    }

    printf("Registering watchdog for PID %d\n", ParentPid);
    Handle = OpenLfiDriver(pLfiDriverDevice);
    if (Handle == INVALID_HANDLE_VALUE) {
        printf("Could not open %s\n", pLfiDriverDevice);
        return FALSE;
    }

    if (!LfiIoCtl(Handle, IOCTL_LFIDRIVER_PS_WATCHDOG, &ParentPid, sizeof(ParentPid))) {
        printf("Could not perform IOCTL %s\n", pLfiDriverDevice);
        CloseHandle(Handle);
        return FALSE;
    }

    CloseHandle(Handle);

    return TRUE;
}