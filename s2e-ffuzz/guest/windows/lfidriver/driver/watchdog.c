//#include <ntddk.h>
#include <ntifs.h>
#include "s2e.h"
#include "hook.h"

#include <WindowsMonitor2.h>

extern LFIDRIVER_KERNEL_STRUCTS g_LfiKernelStructs;

typedef PPEB (*PSGETPROCESSPB)(PEPROCESS Process);
typedef PCHAR (*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);

static PSGETPROCESSPB g_pPsGetProcessPeb;
static GET_PROCESS_IMAGE_NAME g_pGetProcessImageFileName;

NTKERNELAPI
NTSTATUS
PsLookupThreadByThreadId(
    HANDLE ThreadId,
    PETHREAD *Thread
);

static VOID WatchdogThreadNotification(
    IN HANDLE  ProcessId,
    IN HANDLE  ThreadId,
    IN BOOLEAN  Create)
{
    PETHREAD Thread;
    NTSTATUS Status;
    S2E_WINMON2_COMMAND Command;

    S2EMessageFmt("lfidriver: caught thread %s pid=%#x tid=%#x create=%d",
                  Create ? "creation" : "termination", ProcessId, ThreadId, Create);

    //XXX: fails when create is true. Maybe the thread wasn't fully inited yet.
    Status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(Status)) {
        S2EMessageFmt("lfidriver: PsLookupThreadByThreadId failed with %#x", Status);
        Thread = NULL;
    }

    Command.Command = Create ? THREAD_CREATE : THREAD_EXIT;
    Command.Thread.ProcessId = (UINT_PTR) ProcessId;
    Command.Thread.ThreadId = (UINT_PTR) ThreadId;
    Command.Thread.EThread = (UINT_PTR) Thread;
    S2EInvokePlugin("WindowsMonitor2", &Command, sizeof(Command));

    if (Thread) {
        ObDereferenceObject(Thread);
    }
}

static VOID WatchdogProcess(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create)
{
    PEPROCESS Process;
    NTSTATUS Status;
    PPEB Peb;
    CHAR *ImageFileName;
    S2E_WINMON2_COMMAND Command;

    S2EMessageFmt("lfidriver: caught process %s pid=%p parent=%p\n",
                  Create? "creation" : "termination",  ProcessId, ParentId);

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        S2EKillState(0, "PsLookupProcessByProcessId failed");
    }

    ImageFileName = g_pGetProcessImageFileName(Process);

    S2EMessageFmt("lfidriver: process image %s\n", ImageFileName);

    ObDereferenceObject(Process);

    Command.Process.EProcess = (UINT64) Process;
    Command.Process.ProcessId = (UINT64) ProcessId;
    Command.Process.ParentProcessId = (UINT64) ParentId;
    strncpy(Command.Process.ImageFileName, ImageFileName, sizeof(Command.Process.ImageFileName)-1);

    Command.Command = Create ? LOAD_PROCESS : UNLOAD_PROCESS;

    S2EInvokePlugin("WindowsMonitor2", &Command, sizeof(Command));

    if (!Create) {
        if ((DWORD) ProcessId == g_LfiKernelStructs.WatchPid) {
            S2EKillState(0, "lfidriver: caught process termination\n");
        }
    }
}

VOID WatchdogRegisterPid(DWORD Pid)
{
    S2EMessageFmt("lfidriver: watchdog registered pid %x\n", Pid);
    g_LfiKernelStructs.WatchPid = Pid;
}

static VOID EnumerateThreads(PEPROCESS Process)
{
    PLIST_ENTRY Head = (PLIST_ENTRY)((UINT_PTR)(Process) + g_LfiKernelStructs.EProcessThreadListHeadOffset);
    PLIST_ENTRY CurrentThreadLink = Head->Flink;
    while (CurrentThreadLink != Head) {
        UINT_PTR pEThread = (UINT_PTR)(CurrentThreadLink) - (UINT_PTR)g_LfiKernelStructs.EThreadThreadListEntry;
        S2EMessageFmt("lfidriver:    ETHREAD %#p ID=%#x\n", pEThread, PsGetThreadId((PETHREAD) pEThread));
        CurrentThreadLink = CurrentThreadLink->Flink;
    }
}

//XXX: Not safe, must not be interrupted
//Need to lock the list and reference process/thread object while processing them.
static VOID EnumerateProcesses(VOID)
{
    PLIST_ENTRY Head = g_LfiKernelStructs.PsActiveProcessHead;
    PLIST_ENTRY CurrentProcessLink = Head->Flink;

    while (CurrentProcessLink != Head) {
        CHAR *ImageFileName;

        UINT_PTR pEProcess = (UINT_PTR)(CurrentProcessLink) - (UINT_PTR)g_LfiKernelStructs.EProcessActiveProcessLinkOffset;
        ImageFileName = g_pGetProcessImageFileName((PEPROCESS) pEProcess);
        S2EMessageFmt("lfidriver: EPROCESS %#p ID=%#x %s\n", pEProcess, PsGetProcessId((PEPROCESS) pEProcess), ImageFileName);
        EnumerateThreads((PEPROCESS) pEProcess);
        CurrentProcessLink = CurrentProcessLink->Flink;
    }
}

/**
 * The operating system calls this routine to notify the driver when a driver image or a user image
 * (for example, a DLL or EXE) is mapped into virtual memory. This call occurs after the image is
 * mapped and before execution of the image starts.
 *
 * When the main executable image for a newly created process is loaded,
 * the load-image notify routine runs in the context of the new process.
 */
static VOID OnImageLoad(
    PUNICODE_STRING  FullImageName,
    HANDLE  ProcessId,
    PIMAGE_INFO  ImageInfo)
{
    S2E_WINMON2_COMMAND Command;

    S2EMessageFmt("lfidriver: detected image load pid=%p addr=%p size=%#x %wZ kernel=%d allpids=%d\n",
                  ProcessId,
                  ImageInfo->ImageBase,
                  ImageInfo->ImageSize,
                  FullImageName,
                  ImageInfo->SystemModeImage,
                  ImageInfo->ImageMappedToAllPids);

    if (ImageInfo->SystemModeImage) {
        //Ignore drivers for now, we load them differently
        return;
    }

    #if 0 //We have the binaries on disk anyway
    //Page in the image
    __try {
        UINT8 *Data = ImageInfo->ImageBase;
        SIZE_T i = 0;

        ProbeForRead(ImageInfo->ImageBase, ImageInfo->ImageSize, 1);
        while (i < ImageInfo->ImageSize) {
            volatile UINT8 Byte = *Data;
            i += 0x1000;
            Data += 0x1000;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        S2EMessageFmt("  Could not probe for read the module\n");
    }
    #endif

    Command.Command = LOAD_IMAGE;
    Command.Module2.LoadBase = (UINT_PTR) ImageInfo->ImageBase;
    Command.Module2.Size = ImageInfo->ImageSize;
    Command.Module2.Pid = (UINT64) ProcessId;
    Command.Module2.UnicodeModulePath = (UINT_PTR) FullImageName->Buffer;
    Command.Module2.UnicodeModulePathSizeInBytes = FullImageName->Length;
    S2EInvokePlugin("WindowsMonitor2", &Command, sizeof(Command));
}


VOID WatchdogInitialize()
{
    NTSTATUS Status;
    UNICODE_STRING MethodName;

    RtlInitUnicodeString(&MethodName, L"PsGetProcessPeb");
    g_pPsGetProcessPeb = (PSGETPROCESSPB)MmGetSystemRoutineAddress(&MethodName);

    if (!g_pPsGetProcessPeb) {
        S2EKillState(0, "lfidriver: could not find PsGetProcessPeb routine\n");
    }

    RtlInitUnicodeString(&MethodName, L"PsGetProcessImageFileName");
    g_pGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&MethodName);
    
    if (!g_pGetProcessImageFileName) {
        S2EKillState(0, "lfidriver: could not find PsGetProcessImageFileName routine\n");
    }

    Status = PsSetCreateProcessNotifyRoutine(WatchdogProcess, FALSE);
    if (!NT_SUCCESS(Status)) {
        S2EMessageFmt("lfidriver: could not register process watchdog\n");
    }

    Status = PsSetCreateThreadNotifyRoutine(WatchdogThreadNotification);
    if (!NT_SUCCESS(Status)) {
        S2EMessageFmt("lfidriver: could not register thread notification routine\n");
    }

    Status = PsSetLoadImageNotifyRoutine(OnImageLoad);
    if (!NT_SUCCESS(Status)) {
        S2EKillState(0, "lfidriver: could not register image loading notification routine\n");
    }

    EnumerateProcesses();
}

VOID WatchdogDeinitialize()
{
    PsSetCreateProcessNotifyRoutine(WatchdogProcess, TRUE);
    PsRemoveCreateThreadNotifyRoutine(WatchdogThreadNotification);
    PsRemoveLoadImageNotifyRoutine(OnImageLoad);
}
