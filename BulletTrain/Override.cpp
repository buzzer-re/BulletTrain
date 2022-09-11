#include "Override.h"
#include <iostream>


bool Override::ReplaceImage(const wchar_t* proc, const wchar_t* newImagePath, bool self)
{
	// Read PE
	std::wprintf(L"[+] Reading PE file %s [+]\n", newImagePath);
	File newImage(newImagePath);
	if (!newImage.length) {
		std::wprintf(L"[-] Unable to open file, is it available/exists ? [-]\n");
	}
 
	std::wprintf(L"[+] Getting PID of %s [+]\n", proc);
	// Get process PID and Start the PE image replace
	DWORD pid = GetPID(proc);
	if (!pid) return false;

	std::printf("[+] Opening process %d [+]\n", pid);
	// Yep, even if self is true we are going to open our own process
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);

	if (!hProc || hProc == INVALID_HANDLE_VALUE) {
		std::wprintf(L"[-] Unable to open process %s, are you admin ? [-]\n", proc);
		return false;
	}

	BasicPE basicPE;
	if (!basicPE.ParseBuffer(newImage.data)) return false;

	LPVOID newImg = ReplaceImage(hProc, newImage, basicPE);
	if (newImg == nullptr) return false;

	InjectedCodeData iData;
	iData.imageBase = newImg;
	iData.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);
	iData.pLoadLibraryA = reinterpret_cast<f_LoadLibraryA>(LoadLibraryA);
	iData.SafePrint = self;

	// Self code injection
	if (self)
	{
		std::puts("\n\n[+] Parsing IAT and applying relocations [+]\n");
		InternalLoader(&iData);
		return true;
	}


	// Remote code injection
	std::puts("[+] Injecting using CreateRemoteThread technique [+]");
	RemoteBuffer threadArg(hProc);
	threadArg.data = reinterpret_cast<LPVOID>(VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!threadArg.data || !WriteProcessMemory(hProc, threadArg.data, &iData, sizeof(iData), NULL))
	{
		return false;
	}


	RemoteBuffer threadCode(hProc);
	threadCode.data = reinterpret_cast<LPVOID>(VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!threadCode.data || !WriteProcessMemory(hProc, threadCode.data, InternalLoader, 0x1000, NULL))
	{
		return false;
	}

	std::puts("[+] Entering in the valley of despair! Expect no logs from now on [+]");
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0x1000, (LPTHREAD_START_ROUTINE)threadCode.data, threadArg.data, NULL, NULL);

	if (hThread == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	
	// Wait a little to everything be setup 
	Sleep(SLEEP_TIME);
	return true;
}


LPVOID Override::ReplaceImage(HANDLE hProc, const File& target, BasicPE& pe)
{
	// Alloc image memory

	LPVOID imgMem = VirtualAllocEx(hProc, (LPVOID) pe.pOptionalHeader->ImageBase, pe.pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!imgMem)
	{
		std::printf("[+] Unable to allocate address in the image base 0x%llx! relocations will be applied! [+]\n",(ULONG_PTR) pe.pOptionalHeader->ImageBase);
		imgMem = VirtualAllocEx(hProc, NULL, pe.pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!imgMem) {
			std::puts("[-] Error on allocating PE memory [-]\n");
			return nullptr;
		}
		std::printf("[+] Allocated PE memory at base address 0x%llx\n", (ULONG_PTR)imgMem);
		// Ok, something really bad is happening now!
	}

	std::printf("[+] Allocated memory at 0x%llx [+]\n[+] Copying PE header... [+]\n\n\n", (ULONG_PTR) imgMem);
	// Get first section entry

	// Write all header info
	if (!WriteProcessMemory(hProc, imgMem, target.data, pe.pNtHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		std::printf("[-] Unable to copy PE header! [-]");
		VirtualFreeEx(hProc, imgMem, 0, MEM_RELEASE);
		return nullptr;
	}


	std::printf("[+] Writing sections! [+]\n\n");
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pe.pNtHeader);
	// Write sections
	for (auto i = 0; i < pe.pFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			SIZE_T bytesWritten;
			if (!WriteProcessMemory(hProc, (BYTE*) imgMem + pSectionHeader->VirtualAddress, target.data + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, &bytesWritten))
			{
				std::printf("Unable to write section into process memory! error => %d\n", GetLastError());
				VirtualFreeEx(hProc, imgMem, 0, MEM_RELEASE);
				return nullptr;
			}

			std::printf("\t[+] Written %s at 0x%llx [+]\n", pSectionHeader->Name, (ULONG_PTR)imgMem + pSectionHeader->VirtualAddress);
		}
	}

	std::printf("\n[+] Done initial image mapping! [+]\n");
	return imgMem;

}


DWORD Override::GetPID(const wchar_t* proc)
{
	DWORD pid = 0;
	PROCESSENTRY32W pEntry32;
	pEntry32.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	BOOL first = Process32FirstW(hSnap, &pEntry32);

	if (!first) return 0;

	do {
		if (!_wcsicmp(proc, pEntry32.szExeFile))
		{
			pid = pEntry32.th32ProcessID;
			break;
		}

	} while (Process32NextW(hSnap, &pEntry32));

	CloseHandle(hSnap);

	return pid;
}





