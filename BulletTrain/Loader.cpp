#include "Loader.h"

// Import libraries
// Fix realocations
// Run TLS callbacks
// Run entrypoint/dllMain
void __stdcall InternalLoader(InjectedCodeData* iData)
{
	// Basic info
	ULONG_PTR imageBase = reinterpret_cast<ULONG_PTR>(iData->imageBase);
	PIMAGE_DOS_HEADER dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
	PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>((SIZE_T)dosHdr + dosHdr->e_lfanew);
	
	// Get entrypoint, even if is not a DLL
	f_DLL_ENTRY_POINT dllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(ntHdr->OptionalHeader.AddressOfEntryPoint + (SIZE_T)iData->imageBase);

	// Fix realocations
	// Calculate delta between prefeered image base and actual image base
	ULONG_PTR* delta = reinterpret_cast<ULONG_PTR*>(imageBase - ntHdr->OptionalHeader.ImageBase);

	if (delta) {
		if (iData->SafePrint) {
			std::printf("\t[+] Applying relocations! [+]\n");
		}
		// Get reloc directory
		PIMAGE_DATA_DIRECTORY relocDirectory = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
		if (relocDirectory->Size) {
			// Get the Realocation information
			PIMAGE_BASE_RELOCATION pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(imageBase + relocDirectory->VirtualAddress);
			
			while (pBaseReloc->VirtualAddress) {
				// Pick the first entry in the patch array
				WORD* pInfo = reinterpret_cast<WORD*>(pBaseReloc + 1);
				// Calculate the number of patches to be applied by sub the size of the block minus the pBaseReloc struct
				// And then dividing by the size of the pInfo data (WORD), that way we will have all entries inside the reloc tab
				auto numEntries = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				for (int i = 0; i < numEntries; ++i, ++pInfo) {
					// Check if the reloc flag is set
					if (RELOC_FLAG(*pInfo)) {
						// Get the address that need the patch
						ULONG_PTR* patchAddr = reinterpret_cast<ULONG_PTR*>(imageBase + (pBaseReloc->VirtualAddress + (*pInfo & 0xFFF)));
						//std::printf("Apply patch in address: 0x%llx\n", patchAddr);
						
						// Increment the address that are using the image base, with the difference (delta) between the new allocated address
						// and the prefered base address
						*patchAddr += reinterpret_cast<ULONG_PTR>(delta);
					}
				}
				// Get the new entry in the relocation table
				pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<ULONG_PTR>(pBaseReloc) + pBaseReloc->SizeOfBlock);
			}
		}
		if (iData->SafePrint) {
			std::printf("\t[+] Image realocated successfully! [+]\n");
		}
	}

	// FIX IMPORT TABLE
	PIMAGE_DATA_DIRECTORY importDirectory = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(&ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	PIMAGE_IMPORT_DESCRIPTOR impDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(imageBase + importDirectory->VirtualAddress);

	for (; impDescriptor->Name; impDescriptor++)
	{
		char* dllName = reinterpret_cast<char*>(imageBase + impDescriptor->Name);

		if (iData->SafePrint) {
			std::printf("\t[+] Loading %s... [+]\n", dllName);
		}

		HMODULE hModule = iData->pLoadLibraryA(dllName);
		if (hModule == NULL) return; // something is not correct dude

		PIMAGE_THUNK_DATA pOriginalThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + impDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(imageBase + impDescriptor->FirstThunk);

		for (; pOriginalThunkData->u1.AddressOfData; ++pOriginalThunkData, ++pFirstThunk)
		{
			if (!IMAGE_SNAP_BY_ORDINAL((ULONG_PTR)pOriginalThunkData))
			{
				PIMAGE_IMPORT_BY_NAME impName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBase + pOriginalThunkData->u1.AddressOfData);
				UINT_PTR* thunk = reinterpret_cast<UINT_PTR*>(pFirstThunk);
				*thunk = iData->pGetProcAddress(hModule, impName->Name);
			}
		}
	}


	if (iData->SafePrint) {
		std::printf("\n\n[+] Done! close your fingers because we are about to execute! [+]\n");
	}

	dllMain(nullptr, DLL_PROCESS_ATTACH, nullptr);
}