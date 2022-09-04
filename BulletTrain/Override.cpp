#include "Override.h"
#include <iostream>

void __stdcall InternalLoader(InjectedCodeData* iData)
{
	PIMAGE_DOS_HEADER dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(iData->imageBase);
	PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>((SIZE_T)dosHdr + dosHdr->e_lfanew);
	// DLL Entrypoint
	f_DLL_ENTRY_POINT dllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(ntHdr->OptionalHeader.AddressOfEntryPoint + (SIZE_T) iData->imageBase);
	
	// Fix imports




	dllMain(nullptr, DLL_PROCESS_ATTACH, nullptr);
}


bool Override::ReplaceImage(const wchar_t* proc, const wchar_t* newImagePath)
{
	// Read PE
	File newImage(newImagePath);

	if (!newImage.length) return false;
 
	// Get process PID and Start the PE image replace

	DWORD pid = GetPID(proc);
	if (!pid) return false;


	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);

	if (!hProc || hProc == INVALID_HANDLE_VALUE) return false;

	std::cout << "Process opened! replacing image...";
	
	BasicPE basicPE;

	if (!basicPE.ParseBuffer(newImage.data)) return false;

	if (!ReplaceImage(hProc, newImage, basicPE)) return false;

	InjectedCodeData iData;
	iData.imageBase = reinterpret_cast<LPVOID>(basicPE.pOptionalHeader->ImageBase);
	iData.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);
	iData.pLoadLibraryA = reinterpret_cast<f_LoadLibraryA>(LoadLibraryA);

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


	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0x1000, (LPTHREAD_START_ROUTINE)threadCode.data, threadArg.data, NULL, NULL);

	if (hThread == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	system("pause");


	return true;
}


bool Override::ReplaceImage(HANDLE hProc, const File& target, BasicPE& pe)
{


	// Alloc image memory

	LPVOID imgMem = VirtualAllocEx(hProc, (LPVOID)pe.pOptionalHeader->ImageBase, pe.pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!imgMem)
	{
		// Some error handling msg, whatever.. TODO
		return false;

	}

	// Write header

	if (!WriteProcessMemory(hProc, imgMem, target.data, sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS), NULL))
	{
		std::printf("Unable to copy PE header!");
		VirtualFreeEx(hProc, imgMem, 0, MEM_RELEASE);
		return false;
	}

	// Write sections

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pe.pNtHeader);

	for (auto i = 0; i < pe.pFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->PointerToRawData)
		{
			if (!WriteProcessMemory(hProc, (BYTE*)imgMem + pSectionHeader->VirtualAddress, target.data + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, NULL))
			{
				std::printf("Unable to write section into process memory! error => %d\n", GetLastError());
				VirtualFreeEx(hProc, imgMem, 0, MEM_RELEASE);
				return false;
			}
		}
	}



	return true;
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





