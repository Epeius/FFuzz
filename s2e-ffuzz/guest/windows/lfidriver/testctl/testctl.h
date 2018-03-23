#ifndef _TEST_CTL_H_

#define _TEST_CTL_H_

#include <windows.h>

#include <lfictl.h>


INT S2EGetVersionSafe(VOID);
VOID DebugApp(DWORD Pid, DWORD EventId);
char *GetErrorString(DWORD ErrorCode);

typedef struct _S2E_BUG_COMMAND S2E_BUG_COMMAND;
INT S2EInvokeBugCollector(S2E_BUG_COMMAND *Command);

/* This stuff is from psapi.h, which seems
 * to be missing from the DDK. */
DWORD WINAPI GetModuleFileNameExA(
  HANDLE hProcess,
  HMODULE hModule,
  LPTSTR lpFilename,
  DWORD nSize
);

DWORD WINAPI GetModuleBaseNameA(
  HANDLE hProcess,
  HMODULE hModule,
  LPCSTR lpBaseName,
  DWORD nSize
);

#ifdef __cplusplus
extern "C" {
#endif
    HRESULT RunINFSection(LPCSTR szInfFile, LPCSTR szInfSection);
    HRESULT InstallINF(LPCTSTR lpszInfFullPath);
    BOOLEAN WaitForDeviceInstallation(LPCTSTR DeviceId);
#ifdef __cplusplus
}
#endif

static CHAR LfiDriverDevice[] = "\\\\.\\\\LfiDriver";
static CHAR *pLfiDriverDevice = &LfiDriverDevice[0];

HANDLE OpenLfiDriver(PCSTR DeviceName);
BOOL LfiIoCtl(HANDLE Handle, DWORD Code, PVOID Buffer, DWORD Length);

BOOL RegisterWatchdog(VOID);

BOOLEAN StartAutoConfirm(VOID);

#endif
