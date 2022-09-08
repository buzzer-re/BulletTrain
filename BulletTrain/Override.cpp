#include "Override.h"
#include <iostream>

// Import libraries
// Fix realocations
// Run TLS callbacks
// Run entrypoint/dllMain
void __stdcall InternalLoader(InjectedCodeData* iData)
{
	ULONG_PTR imageBase = reinterpret_cast<ULONG_PTR>(iData->imageBase);
	PIMAGE_DOS_HEADER dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
	PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>((SIZE_T)dosHdr + dosHdr->e_lfanew);
	// DLL Entrypoint
	f_DLL_ENTRY_POINT dllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(ntHdr->OptionalHeader.AddressOfEntryPoint + (SIZE_T) iData->imageBase);
	
	// Fix imports
	PIMAGE_DATA_DIRECTORY importDirectory = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	PIMAGE_IMPORT_DESCRIPTOR impDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(imageBase + importDirectory->VirtualAddress);

	for (; impDescriptor->Name; impDescriptor++)
	{
		char* dllName = reinterpret_cast<char*>(imageBase + impDescriptor->Name);
		HMODULE hModule = iData->pLoadLibraryA(dllName);
		if (hModule == NULL) return; // something is not correct dude

		PIMAGE_THUNK_DATA pOriginalThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + impDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + impDescriptor->FirstThunk);

		for (;pOriginalThunkData->u1.AddressOfData; pOriginalThunkData++, pFirstThunk++)
		{
			if (!IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)pOriginalThunkData))
			{
				PIMAGE_IMPORT_BY_NAME impName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBase + pOriginalThunkData->u1.AddressOfData);
				UINT_PTR* thunk = reinterpret_cast<UINT_PTR*>(pFirstThunk);
				*thunk = iData->pGetProcAddress(hModule, impName->Name);

			}
		}
	}


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

	BasicPE basicPE;
	if (!basicPE.ParseBuffer(newImage.data)) return false;

	LPVOID newImg = ReplaceImage(hProc, newImage, basicPE);
	if (newImg == nullptr) return false;

	InjectedCodeData iData;
	iData.imageBase = newImg;
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


LPVOID Override::ReplaceImage(HANDLE hProc, const File& target, BasicPE& pe)
{
	// Alloc image memory

	LPVOID imgMem = VirtualAllocEx(hProc, (LPVOID)pe.pOptionalHeader->ImageBase, pe.pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	if (!imgMem)
	{
		// Some error handling msg, whatever.. TODO
		return nullptr;

	}

	// Get first section entry

	// Write all header info
	if (!WriteProcessMemory(hProc, imgMem, target.data, pe.pNtHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		std::printf("Unable to copy PE header!");
		VirtualFreeEx(hProc, imgMem, 0, MEM_RELEASE);
		return nullptr;
	}


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
		}
	}

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





