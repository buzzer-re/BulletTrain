#pragma once

#include <windows.h>
#include <iostream>


// Thanks Guided Hacking
// Relocation type constants, if has this flag we can apply the realocation
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0xC) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0xC) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG64
#endif


/*
	We define the function pointers because when we are running our injected code
	it's not possible to know where the LoadLibrary and GetProcAddress is located!

	Even if they have fixed location, we must have this information in our code!
	This info will be sent to our remote thread as a parameter, struct InjectedCodeData*

*/

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct InjectedCodeData
{
	LPVOID				imageBase;
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
	BOOL				SafePrint;
};



void __stdcall InternalLoader(InjectedCodeData* iData);
