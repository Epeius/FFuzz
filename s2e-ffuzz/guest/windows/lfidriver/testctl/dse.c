#define USER_APP
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include "psapi.h"

#include <s2e.h>

typedef VOID PATCH_DSE(UINT_PTR LoadBase);
typedef struct PATCH_DSE_HANDLERS {
    UINT32 CheckSum;
    PATCH_DSE *Handler;
} PATCH_DSE_HANDLERS;

static PATCH_DSE Windows8_32_Handler;
static PATCH_DSE Windows8_64_Handler;

#define WIN8_64_CIDLL_CHECKSUM 0x7fd42
#define WIN8_32_CIDLL_CHECKSUM 0x0

static PATCH_DSE_HANDLERS PatchHandlers [] = {
#if defined(_AMD64_)
    {WIN8_64_CIDLL_CHECKSUM, &Windows8_64_Handler},
#else
    {WIN8_32_CIDLL_CHECKSUM, &Windows8_32_Handler},
#endif
};


static VOID PatchDSE(UINT_PTR LoadBase, UINT_PTR NativeBase, UINT_PTR ByteLocation)
{
    UINT_PTR ToPatch = ByteLocation - NativeBase + LoadBase;
    UINT32 Value = 0;
    S2EMessageFmt("PatchDSE: Writing to memory location %p\n", (PVOID)ToPatch);
    S2EWriteMemorySafe((PVOID) ToPatch, &Value, sizeof(Value));
}

static VOID Windows8_32_Handler(UINT_PTR LoadBase)
{
    const UINT_PTR g_CiOptions = 0;
    const UINT_PTR NativeBase = 0;
    PatchDSE(LoadBase, NativeBase, g_CiOptions);
}

static VOID Windows8_64_Handler(UINT_PTR LoadBase)
{
    const UINT_PTR NativeBase = 0x80010000;
    const UINT_PTR g_CiOptions = 0x80022DA8;
    PatchDSE(LoadBase, NativeBase, g_CiOptions);
}

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1
#define DRV_MAX_LEN 1024

UINT_PTR FindDriverBase(PCTSTR DriverName, PTSTR DriverPath, DWORD DriverPathSize)
{
    UINT_PTR Result = 0;
    LPVOID *drivers = NULL;
    DWORD cbNeeded = 0;
    int cDrivers, i;
    TCHAR szDriver[DRV_MAX_LEN + 1];

    //Fetch the required size for the array
    if (!EnumDeviceDrivers(drivers, 0, &cbNeeded)) {
        _tprintf(TEXT("EnumDeviceDrivers failed\n"));
        return Result;
    }

    drivers = (LPVOID *) malloc(cbNeeded);
    if (!drivers) {
        _tprintf(TEXT("Could not allocate memory for driver list\n"));
        return Result;
    }

    if (!EnumDeviceDrivers(drivers, cbNeeded, &cbNeeded)) {
        _tprintf(TEXT("EnumDeviceDrivers failed\n"));
        goto err1;
    }
      
    cDrivers = cbNeeded / sizeof(drivers[0]);

    _tprintf(TEXT("There are %d drivers.\n"), cDrivers);
    for (i=0; i < cDrivers; i++ )
    {
        if(GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
        {
            _tcslwr_s(szDriver, sizeof(TCHAR) * DRV_MAX_LEN);
            if (!_tcsicmp(szDriver, DriverName)) {
                GetDeviceDriverFileName(drivers[i], DriverPath, DriverPathSize);
                Result = (UINT64) drivers[i];
                goto err1;
            }
            
            //_tprintf(TEXT("%d: %s @%p\n"), i, szDriver, drivers[i]);
        }
    }

    err1: free(drivers);  
    return Result; 
}


UINT32 GetModuleCheckSum(PTSTR Filename)
{
    TCHAR System32Dir[MAX_PATH + 1];
    TCHAR ModulePath[MAX_PATH + 1];
    HMODULE hLibrary;
    MODULEINFO moduleInfo;
    UINT32 Result = 0;
    IMAGE_DOS_HEADER *DosHeader;
    IMAGE_NT_HEADERS *NtHeaders;

    if (GetSystemDirectory(System32Dir , MAX_PATH) == 0) {
		_tprintf(_T("Could not get system32 directory\n"));
		return 0; 
	}
   
	if (PathCombine(ModulePath , System32Dir , Filename) == NULL) {
		return 0 ; 
	}

    hLibrary = LoadLibraryEx(ModulePath , 0 , DONT_RESOLVE_DLL_REFERENCES);
    if (!hLibrary) {
        _tprintf(_T("Could not load %s\n"), ModulePath);
        return 0;
    }

    if (!GetModuleInformation(GetCurrentProcess() , hLibrary , &moduleInfo , sizeof(MODULEINFO)))
	{
		_tprintf(_T("Could not get module info for %s\n"), ModulePath);
		goto err1;
	}

    _tprintf(_T("%s is at %p\n"), ModulePath, moduleInfo.lpBaseOfDll);

    DosHeader = (IMAGE_DOS_HEADER *) moduleInfo.lpBaseOfDll;
    NtHeaders = (IMAGE_NT_HEADERS *) ((UINT_PTR) moduleInfo.lpBaseOfDll + DosHeader->e_lfanew);
    
    #if defined(_X86_)
    if (NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        _tprintf(_T("Invalid architecture for %s\n"), ModulePath);
        goto err1;
    }
    #elif defined(_AMD64_)
    if (NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        _tprintf(_T("Invalid architecture for %s\n"), ModulePath);
        goto err1;
    }
    #endif
    
    return NtHeaders->OptionalHeader.CheckSum;

    err1:
    FreeLibrary(hLibrary);
    return Result;
}

BOOLEAN DisableDSE()
{
    UINT32 Checksum;
    INT i;
    TCHAR szDriver[DRV_MAX_LEN + 1];
    UINT_PTR CiBase = FindDriverBase(_T("ci.dll"), szDriver, DRV_MAX_LEN);
    if (!CiBase) {
        _tprintf(_T("Could not find ci.dll\n"));
        return FALSE;
    }

    Checksum = GetModuleCheckSum(_T("ci.dll"));
    _tprintf(_T("ci.dll is at %llx (%s) checksum: %x\n"), CiBase, szDriver, Checksum);

    if (!Checksum) {
        _tprintf(_T("Could not compute checksum for %s\n"), szDriver);
    }
 
    for (i = 0; i < sizeof(PatchHandlers) / sizeof(PatchHandlers[0]); ++i) {
        if (Checksum == PatchHandlers[i].CheckSum) {
            PatchHandlers[i].Handler(CiBase);
            return TRUE;
        }
    }  
    
    _tprintf(_T("Could not find patch for %s\n"), szDriver);
    return FALSE;
}