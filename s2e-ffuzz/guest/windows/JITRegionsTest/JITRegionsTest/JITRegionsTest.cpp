#include "stdafx.h"
#include <Windows.h>
#include <set>

using namespace std;

#define ITERATIONS 10

int _tmain(int argc, _TCHAR* argv[])
{

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	LPTSTR szCmdline = _tcsdup(TEXT("C:\\Windows\\System32\\timeout.exe 20"));

	// Start the child process. 
	if (!CreateProcess(NULL,   // No module name (use command line)
		szCmdline,       // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		) {
		printf("CreateProcess failed (%d).\n", GetLastError());
		return 0;
	}

	set<LPVOID> allocationAddresses;

	for (int i = 0; i < ITERATIONS; i++) {

		size_t size = 0x100 + rand() % 10000;
		LPVOID baseAddress =
			VirtualAllocEx(pi.hProcess,
			NULL,
			size,
			MEM_RESET,
			PAGE_EXECUTE_READWRITE);

		if (baseAddress == NULL) {
			printf("error allocating: %d\n", GetLastError());
			return 1;
		}
		printf("allocated 0x%p (%#x)\n", baseAddress, size);
		allocationAddresses.insert(baseAddress);
	}
	
	for (set<LPVOID>::iterator it = allocationAddresses.begin();
		it != allocationAddresses.end(); ++it) {
		LPVOID baseAddress = *it;

		BOOL ret = VirtualFreeEx(pi.hProcess,
			baseAddress,
			0,
			MEM_RELEASE);

		if (!ret) {
			printf("error on free: %d\n", GetLastError());
			return 1;
		}
		else {
			printf("freed memory at 0x%p succesfully\n", baseAddress);
		}
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}

