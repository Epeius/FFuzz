#define NDIS_MINIPORT_DRIVER
#define NDIS51_MINIPORT   1


#include <ndis.h>
#include <ntdef.h>
#include <wdmsec.h>

#include "s2e.h"
#include "hook.h"
#include "lfictl.h"
#include "crash.h"

#include <StaticStateMerger.h>

DRIVER_UNLOAD DriverUnload;

NTSTATUS LfiOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS LfiClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS LfiIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS RegisterFilesystemFilter (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);

VOID WatchdogRegisterPid(DWORD Pid);
VOID WatchdogInitialize();
VOID WatchdogDeinitialize();

#define NT_DEVICE_NAME          L"\\Device\\LfiDriver"
#define DOS_DEVICE_NAME         L"\\DosDevices\\LfiDriver"

PDEVICE_OBJECT  g_DeviceObject = NULL;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
                     IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING  NtDeviceName;
    UNICODE_STRING  Win32DeviceName;
    PDEVICE_OBJECT  DeviceObject = NULL;

    INT S2EVersion = 0;
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Loading S2E fault injection driver\n");

    InitializeWindowsMonitor2();
    WatchdogInitialize();

    try {
        S2EVersion = S2EGetVersion();
    } except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Could not execute S2E opcode");
        Status = STATUS_NO_SUCH_DEVICE;
        goto err2;
    }

    if (S2EVersion == 0) {
        DbgPrint("Not running in S2E mode");
        Status = STATUS_UNSUCCESSFUL;
        goto err2;
    }

    S2EMessageFmt("lfidriver: Windows build %#x\n", _WIN32_WINNT);

    RtlInitUnicodeString(&NtDeviceName, NT_DEVICE_NAME);
    Status = IoCreateDeviceSecure(
                 DriverObject,
                 0,
                 &NtDeviceName,
                 FILE_DEVICE_UNKNOWN,
                 FILE_DEVICE_SECURE_OPEN,
                 FALSE,
                 &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                 NULL,
                 &DeviceObject
             );

    if (!NT_SUCCESS(Status)) {
        goto err2;
    }

    RtlInitUnicodeString(&Win32DeviceName, DOS_DEVICE_NAME);

    Status = IoCreateSymbolicLink(&Win32DeviceName, &NtDeviceName);
    if (!NT_SUCCESS(Status)) {
        goto err3;
    }

    Status = RegisterFilesystemFilter(DriverObject, RegistryPath);
    if (!NT_SUCCESS(Status)) {
        S2EMessageFmt("lfidriver: RegisterFilesystemFilter failed (status=%#x)", Status);
        goto err4;
    }

    g_DeviceObject = DeviceObject;

#if 0
    RegisterHooks(g_NdisMiniportHooks);
    RegisterHooks(g_NdisProtocolHooks);
    RegisterHooks(g_NtoskrnlHooks);

    #if NTDDI_VERSION >= NTDDI_VISTA
    RegisterHooks(g_Ndis60MiniportHooks);
    #endif

    S2ERegisterMainEntryPointHook();
#endif

    InitializeKernelHooks();
    S2ERegisterMergeCallback();

    if (sizeof(void*) == 8) {
        S2ERegisterReturnHook64();
    }

    //ReloadImports(DriverObject);

    //KeInitializeCallbackRecord(&BugCheckRecord);
    //KeRegisterBugCheckCallback(&BugCheckRecord, BugCheckCallback, NULL, 0, "lfidriver.sys");

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = LfiOpen;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = LfiClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = LfiIoControl;

    /*if (S2EGetVersion()) {
        KeBugCheckEx(0x123, 0x1, 0x2, 0x3, 0x4);
    }*/

    return Status;

    err4: IoDeleteSymbolicLink(&Win32DeviceName);
    err3: IoDeleteDevice(DeviceObject);
    err2: WatchdogDeinitialize();
    return Status;
}


NTSTATUS LfiOpen(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION      IrpSp;
    NTSTATUS                NtStatus = STATUS_SUCCESS;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp->FileObject->FsContext = NULL;

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}

NTSTATUS LfiClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    NTSTATUS                NtStatus;
    PIO_STACK_LOCATION      IrpSp;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    NtStatus = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = NtStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return NtStatus;
}


NTSTATUS LfiIoControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp;
    ULONG FunctionCode;
    NTSTATUS NtStatus = STATUS_SUCCESS;
    ULONG BytesReturned;
    PVOID Buffer;
    ULONG InputBufferLength;

    S2E_BUG_COMMAND Command;
    PVOID CrashOpaque;
    UINT64 CrashOpaqueSize;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    FunctionCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    //OpenContext = (PNDISPROT_OPEN_CONTEXT)IrpSp->FileObject->FsContext;
    BytesReturned = 0;

    Buffer = Irp->AssociatedIrp.SystemBuffer;
    InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    switch (FunctionCode) {
        case IOCTL_LFIDRIVER_REGISTER_MODULE: {
            PCHAR DriverName = Buffer;
            ULONG NameLength = 0;
            if (InputBufferLength) {
                while (DriverName[NameLength] && (NameLength < 128 && (NameLength < InputBufferLength - 1))) {
                    NameLength++;
                }
                DriverName[NameLength] = 0;
                S2EMessageFmt("IOCTL_LFIDRIVER_REGISTER_MODULE (%s)", DriverName);
                //ReloadModuleImports(DeviceObject->DriverObject, DriverName);
                RegisterModule(DriverName);
            } else {
                NtStatus = STATUS_INVALID_USER_BUFFER;
            }
        } break;

        case IOCTL_LFIDRIVER_CUSTOM_BUG: {
            if (InputBufferLength < sizeof(Command)) {
                S2EMessage("lfidriver: IOCTL_LFIDRIVER_CUSTOM_BUG command too short\n");
                NtStatus = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Command = *(S2E_BUG_COMMAND *) Buffer;

            //S2E_BUG_CUSTOM::DescriptionStr is the offset
            //of the string. Convert to absolute pointer.
            if (Command.CustomBug.DescriptionStr >= InputBufferLength) {
                S2EMessage("lfidriver: IOCTL_LFIDRIVER_CUSTOM_BUG invalid description string\n");
                NtStatus = STATUS_INVALID_USER_BUFFER;
                break;
            }

            if (Command.CustomBug.DescriptionStr) {
                Command.CustomBug.DescriptionStr += (UINT64) Buffer;
            }

            InitializeManualCrash(&CrashOpaque, &CrashOpaqueSize);
            Command.CrashOpaque.CrashOpaque = (UINT64) CrashOpaque;
            Command.CrashOpaque.CrashOpaqueSize = CrashOpaqueSize;

            S2EInvokePlugin("BugCollector", &Command, sizeof(Command));
        } break;

        case IOCTL_LFIDRIVER_WINDOWS_USERMODE_BUG: {

            if (InputBufferLength < sizeof(Command)) {
                S2EMessage("lfidriver: IOCTL_LFIDRIVER_WINDOWS_USERMODE_BUG command too short\n");
                NtStatus = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Command = *(S2E_BUG_COMMAND *) Buffer;

            //S2E_BUG_CUSTOM::DescriptionStr is the offset
            //of the string. Convert to absolute pointer.
            if (Command.WindowsUserModeBug.ProgramName >= InputBufferLength) {
                S2EMessage("lfidriver: IOCTL_LFIDRIVER_WINDOWS_USERMODE_BUG invalid program name string\n");
                NtStatus = STATUS_INVALID_USER_BUFFER;
                break;
            }

            if (Command.WindowsUserModeBug.ProgramName) {
                Command.WindowsUserModeBug.ProgramName += (UINT64) Buffer;
            }

            InitializeManualCrash(&CrashOpaque, &CrashOpaqueSize);
            Command.CrashOpaque.CrashOpaque = (UINT64) CrashOpaque;
            Command.CrashOpaque.CrashOpaqueSize = CrashOpaqueSize;

            S2EInvokePlugin("BugCollector", &Command, sizeof(Command));
        } break;

        case IOCTL_LFIDRIVER_CRASH_KERNEL: {
            KeBugCheck(0xDEADDEAD);
        } break;

        case IOCTL_LFIDRIVER_PS_WATCHDOG: {
            DWORD Pid;
            if (InputBufferLength != sizeof(DWORD)) {
                S2EMessageFmt("lfidriver: IOCTL_LFIDRIVER_PS_WATCHDOG command size must be %d but is %d\n",
                    sizeof(DWORD), InputBufferLength);
                NtStatus = STATUS_INVALID_USER_BUFFER;
                break;
            }

            WatchdogRegisterPid(*(DWORD*)Buffer);
        } break;

        default: {
            NtStatus = STATUS_NOT_SUPPORTED;
        } break;
    }

    if (NtStatus != STATUS_PENDING) {
        Irp->IoStatus.Information = BytesReturned;
        Irp->IoStatus.Status = NtStatus;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return NtStatus;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING Win32DeviceName;
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Unloading S2E fault injection driver");

    RtlInitUnicodeString(&Win32DeviceName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&Win32DeviceName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    WatchdogDeinitialize();
}


VOID BugCheckCallback(PVOID Buffer, ULONG Length)
{
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);
    S2EKillState(0, "BSOD - lfidriver detected kernel crash");
}
