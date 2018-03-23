// HeapSprayTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <set>

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	size_t size = 0x100000 + rand() % 100000;

	while (true) {
		LPVOID baseAddress =
			VirtualAlloc(
			NULL,
			size,
			MEM_RESET,
			PAGE_READWRITE);

		if (baseAddress == NULL) {
			int error = GetLastError();
			printf("error allocating: %d\n", error);
			if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY) {
				printf("out of memory\n");
			}
			return 1;
		}
		printf("allocated 0x%p (%#x)\n", baseAddress, size);
	}

	return 0;
}

