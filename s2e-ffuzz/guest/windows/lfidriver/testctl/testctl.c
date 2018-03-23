#define USER_APP
#pragma warning(disable:4201)

#include <windows.h>
#include <winreg.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <s2e.h>

#include <hook.h>
#include <lfictl.h>
#include "testctl.h"
#include <searcher.h>
#include <symbhw.h>

INT S2EGetVersionSafe(VOID)
{
    /* Avoid crashing with illegal instruction when
     * running outside S2E */
    __try {
        return S2EGetVersion();
    }  __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

char *GetErrorString(DWORD ErrorCode)
{
    char *err;
    if (!FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                       NULL,
                       ErrorCode,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
                       (LPSTR) &err,
                       0,
                       NULL)) {
        return NULL;
    }

    return err;
}

typedef int (*cmd_handler_t)(const char **args);

typedef struct _cmd_t {
    char *name;
    cmd_handler_t handler;
    int args_count;
    const char *description;
    const char *arg_desc[4];
} cmd_t;


HANDLE OpenLfiDriver(PCSTR DeviceName)
{
    HANDLE Handle;
    Handle = CreateFileA(DeviceName,
                        GENERIC_READ|GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        (HANDLE) INVALID_HANDLE_VALUE);
    return Handle;
}

BOOL LfiIoCtl(HANDLE Handle, DWORD Code, PVOID Buffer, DWORD Length)
{
    CHAR Output[128];
    DWORD BytesReturned;
    BOOL Ret = DeviceIoControl(Handle, Code, Buffer, Length, Output, sizeof(Output), &BytesReturned, NULL);
    if (!Ret) {
        S2EMessageFmt("LfiIoCtl failed (%s)\n", GetErrorString(GetLastError()));
    }
    return Ret;
}

int handler_register(const char **args)
{
    PCSTR ModuleName = args[0];

    HANDLE Handle = OpenLfiDriver(pLfiDriverDevice);
    if (Handle == INVALID_HANDLE_VALUE) {
        printf("Could not open %s\n", pLfiDriverDevice);
        return -1;
    }

    printf("Registering %s...\n", ModuleName);
    if (!LfiIoCtl(Handle, IOCTL_LFIDRIVER_REGISTER_MODULE, (PVOID) ModuleName, (DWORD)(strlen(ModuleName) + 1))) {
        printf("Could not perform IOCTL %s\n", pLfiDriverDevice);
        CloseHandle(Handle);
        return -1;
    }

    CloseHandle(Handle);
    return 0;
}

INT S2EInvokeBugCollector(S2E_BUG_COMMAND *Command)
{
    OSVERSIONINFO OSVersion;
    HANDLE hDriver;
    UINT8 *Buffer;
    PCSTR String;
    size_t BufferSize, StringSize;
    DWORD IoCtlCode;

    OSVersion.dwOSVersionInfoSize = sizeof(OSVersion);
    if (!GetVersionEx(&OSVersion)) {
        S2EMessage("testctl: could not determine OS version\n");
    }

    Command->CrashOpaque.CrashOpaque = 0;
    Command->CrashOpaque.CrashOpaqueSize = 0;

    /**
     * Windows XP: invoke the plugin directly, because it can generate
     * crash dump info by itself. Later versions need support from lfidriver.
     */
    if (OSVersion.dwMajorVersion == 5 && OSVersion.dwMinorVersion == 1) {
        if (Command->Command == CUSTOM_BUG) {
            __s2e_touch_string((PCSTR) (UINT_PTR) Command->CustomBug.DescriptionStr);
        } else if (Command->Command == WINDOWS_USERMODE_BUG) {
            __s2e_touch_string((PCSTR) (UINT_PTR) Command->WindowsUserModeBug.ProgramName);
        }
        S2EInvokePlugin("BugCollector", Command, sizeof(*Command));
        /* Not supposed to return */
        return 0;
    }

    hDriver = OpenLfiDriver(pLfiDriverDevice);
    if (hDriver == INVALID_HANDLE_VALUE) {
        S2EMessageFmt("testctl: could not open %s\n", pLfiDriverDevice);
        return -1;
    }

    if (Command->Command == CUSTOM_BUG) {
        String = (PCSTR) (UINT_PTR) Command->CustomBug.DescriptionStr;
        Command->CustomBug.DescriptionStr = sizeof(*Command);
        IoCtlCode = IOCTL_LFIDRIVER_CUSTOM_BUG;
    } else if (Command->Command == WINDOWS_USERMODE_BUG) {
        String = (PCSTR) (UINT_PTR) Command->WindowsUserModeBug.ProgramName;
        Command->WindowsUserModeBug.ProgramName = sizeof(*Command);
        IoCtlCode = IOCTL_LFIDRIVER_WINDOWS_USERMODE_BUG;
    } else {
        return -1;
    }

    StringSize = (strlen(String)+1)*sizeof(String[0]);
    BufferSize = sizeof(*Command) + StringSize;
    Buffer = (UINT8 *)malloc(BufferSize);
    if (!Buffer) {
        CloseHandle(hDriver);
        return -1;
    }

    memcpy(Buffer + sizeof(*Command), String, StringSize);
    memcpy(Buffer, Command, sizeof(*Command));

    if (!LfiIoCtl(hDriver, IoCtlCode, Buffer, (DWORD) BufferSize)) {
        S2EMessageFmt("testctl: could not issue ioctl\n");
    }

    free(Buffer);
    CloseHandle(hDriver);
    return 0;
}

int handler_bug(const char **args)
{
    const UINT64 code = strtol(args[0], NULL, 0);
    const char *description = args[1];

    S2E_BUG_COMMAND Command;

    printf("Custom bug code %#llx - %s\n", code, description);

    Command.Command = CUSTOM_BUG;
    Command.CustomBug.CustomCode = code;
    Command.CustomBug.DescriptionStr = (UINT_PTR) description;

    if (!S2EGetVersionSafe()) {
        fprintf(stderr, "testctl: not running in S2E mode\n");
        return -1;
    }

    return S2EInvokeBugCollector(&Command);
}

/**
 * Use the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
 * key to invoke s2edbg.exe.
 *
 * Add or edit the Debugger value, using a REG_SZ string that specifies the
 * command line for the debugger.
 *
 * "C:\test\testctl.exe" %ld %ld
 *
 * s2edbg.exe -p pid -e eventhandle
 */

int handler_debug(const char **args)
{
    long pid = strtol(args[0], NULL, 0);
    long event_id = strtol(args[1], NULL, 0);

    printf("Program with pid %d crashed (event id: %#x)\n", pid, event_id);

    DebugApp(pid, event_id);
    //system("pause");
    return 0;
}

static int register_debug(const char *AeDebugKey)
{
    HMODULE hModule;
    CHAR path[MAX_PATH], str[MAX_PATH];
    HKEY Key;
    LSTATUS Status = RegCreateKeyA(HKEY_LOCAL_MACHINE, AeDebugKey, &Key);
    if (Status != ERROR_SUCCESS) {
        char *err = GetErrorString(Status);
        printf("Could not open key %s (%#x)\n", AeDebugKey, Status);
        LocalFree(err);
        return -1;
    }


    hModule = GetModuleHandle(NULL);
    GetModuleFileNameA(hModule, path, MAX_PATH);
    printf("Setting JIT debugger to %s\n", path);

    sprintf_s(str, sizeof(str), "\"%s\" debug %%ld %%ld", path);
    printf("Writing registry key value %s\n", str);

    Status = RegSetValueExA(Key, "Debugger", 0, REG_SZ, (const BYTE*) str, (DWORD) strlen(str));
    printf("Status %#x\n", Status);
    if (Status != ERROR_SUCCESS) {
        char *err = GetErrorString(Status);
        printf("Could not register %s as a JIT debugger (%#x - %s)\n", AeDebugKey, Status, err);
        LocalFree(err);
    }

    Status = RegSetValueExA(Key, "Auto", 0, REG_SZ, (const BYTE*) "1", 1);
    if (Status != ERROR_SUCCESS) {
        char *err = GetErrorString(Status);
        printf("Could not enable autostart for JIT debugger (%#x - %s)\n", AeDebugKey, Status, err);
        LocalFree(err);
    }

    RegCloseKey(Key);

    return 0;
}

static void disable_windows_error_reporting()
{
    const char *WerPath = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting";
    HKEY Key;

    LSTATUS Status = RegCreateKeyA(HKEY_LOCAL_MACHINE, WerPath, &Key);
    if (Status != ERROR_SUCCESS) {
        char *err = GetErrorString(Status);
        printf("Could not open key %s (%#x)\n", WerPath, Status);
        LocalFree(err);
        return;
    }

    Status = RegSetValueExA(Key, "DontShowUI", 0, REG_SZ, (const BYTE*) "1", 1);
    if (Status != ERROR_SUCCESS) {
        char *err = GetErrorString(Status);
        printf("Could not disable WER (%#x - %s)\n", WerPath, Status, err);
        LocalFree(err);
    }

    RegCloseKey(Key);
}

int handler_register_debug(const char **args)
{
    const char *Path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
    #if defined(_AMD64_)
    const char *WowPath = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
    #endif

    register_debug(Path);

    #if defined(_AMD64_)
    register_debug(WowPath);
    #endif

    printf("Disabling WER...\n");
    disable_windows_error_reporting();

    args;
    return 0;
}

int handler_inst_netprot(const char **args)
{
    RunINFSection(args[0], args[1]);
    return 0;
}

int handler_crash(const char **args)
{
    *(char *) 0 = 0;
    args;
    return 0;
}

int handler_kernel_crash(const char **args)
{
    HANDLE hDriver = OpenLfiDriver(pLfiDriverDevice);
    if (hDriver == INVALID_HANDLE_VALUE) {
        S2EMessageFmt("testctl: could not open %s\n", pLfiDriverDevice);
        return -1;
    }

    S2EMessage("testctl: crashing the kernel...");
    if (!LfiIoCtl(hDriver, IOCTL_LFIDRIVER_CRASH_KERNEL, NULL, 0)) {
        printf("Could not perform IOCTL %s\n", pLfiDriverDevice);
        CloseHandle(hDriver);
        return -1;
    }

    CloseHandle(hDriver);
    UNREFERENCED_PARAMETER(args);
    return 0;
}



int handler_beep(const char **args)
{
    DWORD Frequency = strtol(args[0], NULL, 0);
    DWORD Duration = strtol(args[1], NULL, 0);
    Beep(Frequency, Duration);
    return 0;
}




/**
 * Windows 8 may show all sorts of dialogues asking the user
 * to confirm the driver installation. We want testing to be
 * automated, and therefore need to confirm this dialogues
 * automatically.
 */
int handler_autoconfirm(const char **args)
{
    UNREFERENCED_PARAMETER(args);

    StartAutoConfirm();

    return 0;
}

BOOLEAN DisableDSE();
int handler_disable_dse(const char **args)
{
    UNREFERENCED_PARAMETER(args);
    return !DisableDSE();
}

int handler_fork(const char **args)
{
    CHAR Buffer;
    UNREFERENCED_PARAMETER(args);

    S2EMakeConcolic(&Buffer, sizeof(Buffer), "testctl_fork");
    if (Buffer) {
        S2EMessage("testctl: fork: 1");
        return 1;
    } else {
        S2EMessage("testctl: fork: 0");
        return 0;
    }
}

int handler_watchdog(const char **args)
{
    UNREFERENCED_PARAMETER(args);
    RegisterWatchdog();
    return 0;
}

int handler_hotplug(const char **args)
{
    BOOLEAN Plugin = args[0][0] == '1';
    if (Plugin) {
        printf("Plugging devices");
    } else {
        printf("Unplugging devices");
    }

    SymbhwHotPlug(Plugin);
    return 0;
}

int handler_select_next_pci_config(const char **args)
{
    BOOLEAN Ret;
    printf("Selecting an alternate PCI configuration... ");
    if (args[0][0] == '0') {
        Ret = SymbhwSelectNextConfig();
    } else {
        Ret = SymbhwSelectNextConfigAndNotify();
    }

    printf("%s\n", Ret ? "OK" : "No more configs to try");
    return Ret ? 0 : -1;
}

int handler_installinf(const char **args)
{
    TCHAR szInfFile[MAX_PATH + 1];
    mbstowcs(szInfFile, args[0], MAX_PATH);
    InstallINF(szInfFile);
    return 0;
}

int handler_waitdev(const char **args)
{
    TCHAR devId[MAX_PATH + 1];
    INT Timeout = 100000;
    mbstowcs(devId, args[0], MAX_PATH);

    while (Timeout > 0) {
        printf("Waiting for device %s...\n", args[0]);
        if (WaitForDeviceInstallation(devId)) {
            break;
        }
        Sleep(2000);
    }

    return 0;
}

int handler_sleep(const char **args)
{
    DWORD Timeout = atol(args[0]);
    Sleep(Timeout);
    return 0;
}

int handler_pathdone(const char **args)
{
    UNREFERENCED_PARAMETER(args);
    S2ESetPhaseNumber(1);
    return 0;
}

int handler_waitlfi(const char **args)
{
    HANDLE hDriver;
    UNREFERENCED_PARAMETER(args);

    do {
        S2EMessageFmt("testctl: waiting for lfidriver...");
        hDriver = OpenLfiDriver(pLfiDriverDevice);
    } while (hDriver == INVALID_HANDLE_VALUE);

    CloseHandle(hDriver);
    S2EMessageFmt("testctl: lfidriver loaded.");
    return 0;
}

#define COMMAND(c, args, desc, ...) { #c, handler_##c, args, desc, {__VA_ARGS__} }

static cmd_t s_commands[] = {
    COMMAND(register, 1, "Register a driver that is already loaded.",
                         "Name of the driver (e.g., driver.sys)."),
    COMMAND(bug,      2, "Signals a custom bug to the test engine.",
                         "Custom code (e.g., 0x1234)",
                         "Description"),
    COMMAND(debug,    2, "Handle debug request from Windows",
                         "Pid of the program that crashed",
                         "Event handle"),

    COMMAND(register_debug, 0, "Registers testctl as a Windows JIT debugger.",
                         NULL),

    COMMAND(crash, 0, "Just crashes",
                         NULL),

    COMMAND(kernel_crash, 0, "Crashes the kernel",
                             NULL),

    COMMAND(beep, 2, "Beeps",
                      "Frequency (hz)",
                      "Duration (ms)",
                      NULL),

    COMMAND(inst_netprot, 2, "Installs network protocol driver",
                             "Path to INF file",
                             "PNP device ID"),

    COMMAND(disable_dse, 0, "Disable driver signing enforcement",
                             NULL),

    COMMAND(autoconfirm, 0, "Validates device driver dialogues",
                            NULL),
    COMMAND(fork, 0, "Forks the current state",
                            NULL),

    COMMAND(watchdog, 0, "Registers a watchdog for the parent process",
                         NULL),

    COMMAND(hotplug, 1, "Plugs in symbolic all registered symbolic devices",
                         "1: plugin the devices, 0: unplug them",
                         NULL),

    COMMAND(select_next_pci_config, 1, "Activates an alternate config for the tested PCI device",
                                       "0: select, 1: check if config was already explored first",
                                        NULL),

    COMMAND(installinf, 1, "Copies the INF file to the system folder",
                           "Path to INF file",
                            NULL),

    COMMAND(waitdev, 1, "Waits until the specified device is installed",
                           "Device identifier (e.g., \\PCI\\VEN_...)",
                            NULL),

    COMMAND(sleep, 1, "Waits x milliseconds",
                        "Milliseconds",
                        NULL),

    COMMAND(pathdone, 0, "Signals the searcher that the initial concolic path is finished",
                        NULL),

    COMMAND(waitlfi, 0, "Waits for the lfidriver to finish loading",
        NULL),

    { NULL, NULL, 0, NULL }
};

static void print_commands(void)
{
    unsigned i = 0;
    unsigned j = 0;
    printf("%-15s  %s %s\n\n", "Command name", "Argument count", "Description");
    while(s_commands[i].handler) {
        printf("%-15s  %d              %s\n", s_commands[i].name,
               s_commands[i].args_count, s_commands[i].description);

        for (j = 0; s_commands[i].arg_desc[j]; ++j) {
            printf("                                arg %d: %s\n", j, s_commands[i].arg_desc[j]);
        }

        ++i;
    }
}

static int find_command(const char *cmd)
{
    unsigned i = 0;
    while(s_commands[i].handler) {
        if (!strcmp(s_commands[i].name, cmd)) {
            return i;
        }
        ++i;
    }
    return -1;
}

int __cdecl main(int argc, const char **argv)
{
    const char *cmd;
    int cmd_index;

    if (argc < 2) {
        print_commands();
        return -1;
    }

    cmd = argv[1];
    cmd_index = find_command(cmd);

    if (cmd_index == -1) {
        printf("Command %s not found\n", cmd);
        return -1;
    }

    argc -= 2;
    ++argv;
    ++argv;

    if (argc != s_commands[cmd_index].args_count) {
        printf("Invalid number of arguments supplied (%d instead of %d)\n",
               argc, s_commands[cmd_index].args_count);
        return -1;
    }

    return s_commands[cmd_index].handler(argv);
}
