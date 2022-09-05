#include "BasicPE.h"
#include <iostream>

bool BasicPE::ParseBuffer(BYTE* buff)
{
	pBuff = reinterpret_cast<ULONG_PTR>(buff);
	pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBuff);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

	pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(buff + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeader->OptionalHeader;
	pFileHeader = &pNtHeader->FileHeader;

    return true;
}


// Simple function that just print all the imported DLLS and functions
void BasicPE::PrintImports() const
{
	IMAGE_DATA_DIRECTORY* importDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR impDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBuff + importDirectory->VirtualAddress);
	
	for (; impDescriptor->Name; impDescriptor++)
	{
		std::printf("Fixing IAT...\n");

		char* dllName = reinterpret_cast<char*>(pBuff + impDescriptor->Name);
		HMODULE hDll = LoadLibraryA(dllName);
		std::printf("Loaded %s\n", dllName);

		PIMAGE_THUNK_DATA pOriginalThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(pBuff + impDescriptor->OriginalFirstThunk);
		// Why is called ULONG_PTR if is not a pointer ? 
		ULONG_PTR* pFirstThunk = reinterpret_cast<ULONG_PTR*>(pBuff + impDescriptor->FirstThunk);

		while (pOriginalThunkData->u1.AddressOfData)
		{
			if (!IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)pOriginalThunkData))
			{
				// get func name
				PIMAGE_IMPORT_BY_NAME impName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBuff + pOriginalThunkData->u1.AddressOfData);
				*pFirstThunk = reinterpret_cast<ULONG_PTR>(GetProcAddress(hDll, impName->Name));
				std::printf("Fixed func: %s at 0x%x\n", impName->Name, pFirstThunk);
			}
			pOriginalThunkData++;
		}
	}
}


