#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include "IOUtils.h"
#include "BasicPE.h"

/*
	We define the function pointers because when we are running our injected code
	it's not possible to know where the LoadLibrary and GetProcAddress is located!

	Even if they have fixed location, we must have this information in our code! 
	This info will be sent to our remote thread as a parameter, struct MapperData*

*/

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct InjectedCodeData 
{
	LPVOID imageBase;
	f_LoadLibraryA		pLoadLibraryA;
	f_GetProcAddress	pGetProcAddress;
};

class RemoteBuffer
{
public:
	RemoteBuffer(HANDLE hProc) : data(nullptr), size(0), hProc(hProc) {}
	~RemoteBuffer() {
		if (data != nullptr)
		{
			VirtualFreeEx(hProc, data, 0, MEM_RELEASE);
		}
	}

	HANDLE hProc;
	LPVOID data;
	ULONG size;
};


class Override
{
public:
	bool ReplaceImage(const wchar_t* proc, const wchar_t* newImagePath);
	DWORD GetPID(const wchar_t* proc);

private:
	LPVOID ReplaceImage(HANDLE hProc, const File& target, BasicPE& pe);
};

