#define USER_APP

#pragma warning(disable:4706)
#pragma warning(disable:4201)

#include <stdio.h>
#include <windows.h>

#include <s2e.h>
#include <hook.h>
#include "testctl.h"

BOOL GetProcessName(DWORD Pid, LPSTR Name, DWORD MaxLen)
{
    HANDLE hProcess = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        FALSE, Pid);
    if (!hProcess) {
        printf("testctl: OpenProcess failed\n");
        return FALSE;
    }

    if (!GetModuleBaseNameA(hProcess, NULL, Name, MaxLen)) {
        char *Error = GetErrorString(GetLastError());
        printf("testctl: GetModuleFileName failed %#s\n", Error);
        LocalFree(Error);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hProcess);
    return TRUE;
}

#if defined(_AMD64_)
static BOOL IsWow64(DWORD Pid, PBOOL Result)
{
    BOOL Ret;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);

    if (!hProcess) {
        S2EMessageFmt("testctl: Could not open process pid %d\n", Pid);
        return FALSE;
    }

    Ret = IsWow64Process(hProcess, Result);

    CloseHandle(hProcess);
    return Ret;
}
#endif

static VOID PrintThreadContext(DWORD Pid, DWORD Tid)
{
    HANDLE hThread;
    CONTEXT Context;
    #if defined(_AMD64_)
    BOOL Wow = FALSE;
    #endif

    S2EMessageFmt("testctl: Printing thread context (tid: %u)\n", Tid);

    /* Retrieve thread context information */
    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, Tid);
    if (hThread == NULL) {
        S2EMessageFmt("testctl: Could not open thread tid %d\n", Tid);
        goto e0;
    }

    #if defined(_AMD64_)
    if (!IsWow64(Pid, &Wow)) {
        S2EMessageFmt("testctl: Could not decide if thread %d is syswow64 process\n", Tid);
        goto e1;
    }
    #else
    UNREFERENCED_PARAMETER(Pid);
    #endif

    Context.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(hThread, &Context)) {
        S2EMessageFmt("testctl: Could not get context of thread %d\n", Tid);
        goto e1;
    }

    #if defined(_AMD64_)
    S2EMessageFmt("testctl: RIP:%#llx RSP:%#llx RBP:%#llx \n", Context.Rip, Context.Rsp, Context.Rbp);
    S2EMessageFmt("testctl: RAX:%#llx RCX:%#llx RDX:%#llx RBX:%#llx\n", Context.Rax, Context.Rcx, Context.Rdx, Context.Rbx);
    S2EMessageFmt("testctl: RSI:%#llx RDI:%#llx\n", Context.Rdi, Context.Rdi);
    #else
    S2EMessageFmt("testctl: Eip: %#x\n", Context.Eip);
    #endif

e1: CloseHandle(hThread);
e0: return;
}

VOID PrintExceptionRecord(DWORD Pid, DWORD Tid, const EXCEPTION_RECORD *Record)
{
    DWORD i;
    CHAR ProgramName[MAX_PATH + 1] = {0};
    if (!GetProcessName(Pid, ProgramName, sizeof(ProgramName) - 1)) {
        S2EMessageFmt("testctl: GetProcessName failed\n");
    }

    S2EMessageFmt("testctl: Exception record for %s - pid: %u\n", ProgramName, Pid);
    S2EMessageFmt("testctl: Code: %#x Flags: %#x Address: %p NumParams: %u\n",
                  Record->ExceptionCode, Record->ExceptionFlags, Record->ExceptionAddress,
                  Record->NumberParameters);

    for (i = 0; i < Record->NumberParameters; ++i) {
        S2EMessageFmt("testctl: param[%d]: %#llx\n", i, (UINT64) Record->ExceptionInformation[i]);
    }

    PrintThreadContext(Pid, Tid);
}

int ReportBug(DWORD Pid, const EXCEPTION_RECORD *Record)
{
    S2E_BUG_COMMAND Command;
    CHAR ProgramName[MAX_PATH + 1] = {0};

    Command.Command = WINDOWS_USERMODE_BUG;
    Command.WindowsUserModeBug.Pid = Pid;
    Command.WindowsUserModeBug.ExceptionAddress = (UINT64) Record->ExceptionAddress;
    Command.WindowsUserModeBug.ExceptionCode = Record->ExceptionCode;
    Command.WindowsUserModeBug.ExceptionFlags = Record->ExceptionFlags;
    Command.WindowsUserModeBug.ProgramName = 0;

    if (GetProcessName(Pid, ProgramName, sizeof(ProgramName) - 1)) {
        Command.WindowsUserModeBug.ProgramName = (UINT64) ProgramName;
    } else {
        printf("testctl: GetProcessName failed\n");
    }

    printf("testctl: Program name: %s\n", ProgramName);

    if (!S2EGetVersionSafe()) {
        printf("testctl: Not running in S2E mode\n");
        return -1;
    }

    return S2EInvokeBugCollector(&Command);
}

VOID DebugApp(DWORD Pid, DWORD EventId)
{
    BOOL Attached = FALSE;
    DEBUG_EVENT DebugEvent;
    EXCEPTION_RECORD LastExceptionRecord;
    DWORD ContinueFlag = DBG_CONTINUE;
    BOOL Ret = DebugActiveProcess(Pid);
    if (!Ret) {
        printf("testctl: Could not debug process %d\n", Pid);
        return;
    }

    while ((Ret = WaitForDebugEvent(&DebugEvent, 1000))) {

        printf("testctl: Event code %x\n", DebugEvent.dwDebugEventCode);

        switch(DebugEvent.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                S2EMessageFmt("CREATE_PROCESS_DEBUG_EVENT filename: %s\n", DebugEvent.u.CreateProcessInfo.lpImageName);
                break;

            case EXIT_PROCESS_DEBUG_EVENT: {
                S2EMessageFmt("EXIT_PROCESS_DEBUG_EVENT\n");
                ReportBug(Pid, &LastExceptionRecord);
            }
            break;

            case EXCEPTION_DEBUG_EVENT: {
                DWORD ExceptionCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
                S2EMessageFmt("EXCEPTION_DEBUG_EVENT pid: %x tid: %x\n"
                       "code: %#x "
                       "address: %#x "
                       "flags: %#x "
                       "first chance: %d\n",
                       DebugEvent.dwProcessId,
                       DebugEvent.dwThreadId,
                       ExceptionCode,
                       DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress,
                       DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags,
                       DebugEvent.u.Exception.dwFirstChance);

                PrintExceptionRecord(Pid, DebugEvent.dwThreadId, &DebugEvent.u.Exception.ExceptionRecord);

                if (!Attached && (ExceptionCode == EXCEPTION_BREAKPOINT)) {
                    //printf("Attached!\n");
                    SetEvent((HANDLE) EventId);
                    CloseHandle((HANDLE) EventId);
                    Attached = TRUE;
                }

                LastExceptionRecord = DebugEvent.u.Exception.ExceptionRecord;

                if (!DebugEvent.u.Exception.dwFirstChance) {
                    ReportBug(Pid, &DebugEvent.u.Exception.ExceptionRecord);
                } else {
                    ContinueFlag = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            break;

            default: {
                S2EMessageFmt("testctl: Unhandled event code %d\n", DebugEvent.dwDebugEventCode);
            }
        }

        if (!ContinueDebugEvent(DebugEvent.dwProcessId,
                DebugEvent.dwThreadId, ContinueFlag)) {
            printf("testctl: Failed ContinueDebugEvent\n");
        }
    }

    //DebugActiveProcessStop(Pid);
    EventId;
}
