#include "stdafx.h"


#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <set>

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

#define TARGET_PROCESS _T("AcroRd32")

using namespace std;

int PrintProcInfo(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (hProcess == NULL)
		return 1;

	TCHAR imageFileName[MAX_PATH];
	GetProcessImageFileName(hProcess, imageFileName, MAX_PATH);

	if (StrStr(imageFileName, TARGET_PROCESS) == NULL) {
		return 0;
	}

	set<PVOID> modules;

	_tprintf(TEXT("process %s, pid = %u\n"), imageFileName, processID);

	// Get a list of all the modules in this process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			TCHAR szModName[MAX_PATH];
			// Get the full path to the module's file.
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR))) {
				// Print the module name and handle value.
				_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
				modules.insert(hMods[i]);
			}
		}
	}

	printf("Memory map\n     Start:       End (      size) prot type\n");
	MEMORY_BASIC_INFORMATION mbi;
	unsigned long long start = 0;
	PVOID old_base_addr = 0;
	mbi.BaseAddress = (void*) 1;
	set<PVOID>::iterator it;
	while (mbi.BaseAddress != old_base_addr) {
		old_base_addr = mbi.BaseAddress;

		memset(&mbi, '\0', sizeof(MEMORY_BASIC_INFORMATION));
		int ret = VirtualQueryEx(hProcess, (void*)start, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (ret == 0) {
			break;
		}

		if (mbi.Type == 0) {
			goto __end__;
		}

		unsigned end = (unsigned) mbi.BaseAddress + (unsigned) mbi.RegionSize;
		_tprintf(TEXT("%#10x:%#10x (%#10x) "), mbi.BaseAddress, end, mbi.RegionSize);

		bool isExec = ((mbi.Protect & 0xf0) != 0);
		if (isExec) {
			switch (mbi.Protect) {
			case PAGE_EXECUTE:
				printf("--x ");
				break;
			case PAGE_EXECUTE_READ:
				printf("r-x ");
				break;
			case PAGE_EXECUTE_READWRITE:
			case PAGE_EXECUTE_WRITECOPY:
				printf("rwx ");
				break;
			default:
				printf("??? ");
			}
		} else {
			printf("--- ");
		}

		switch (mbi.Type) {
		case MEM_IMAGE:
			_tprintf(TEXT("img "));
			it = modules.find(mbi.BaseAddress);
			if (it != modules.end()) {
				PVOID hMod = *it;
				TCHAR szModName[MAX_PATH];
				if (GetModuleFileNameEx(hProcess, (HMODULE) hMod, szModName,
					sizeof(szModName) / sizeof(TCHAR))) {
					_tprintf(TEXT("\t%s\n"), szModName);
				}
			}
			_tprintf(TEXT("\n"));
			break;
		case MEM_PRIVATE:
			_tprintf(TEXT("pri\n"));
			break;
		case MEM_MAPPED:
			_tprintf(TEXT("map\n"));
			break;
		default:
			_tprintf(TEXT("unknown (%#x)\n"), mbi.Type);
			break;
		}
__end__:		
		start += mbi.RegionSize;
		if (mbi.RegionSize == 0)
			break;
	}
	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}


int _tmain(int argc, _TCHAR* argv[])
{
	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcesses;
	unsigned int i;

	// Get the list of PIDs
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return 1;

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		PrintProcInfo(aProcesses[i]);
	}
#if 0
	printf("EXE  = %#x ALL = %#x COPY = %#x READ = %#x WRITE = %#x\n",
		FILE_MAP_EXECUTE,
		FILE_MAP_ALL_ACCESS,
		FILE_MAP_COPY,
		FILE_MAP_READ,
		FILE_MAP_WRITE);
#endif // 0

	return 0;
}

