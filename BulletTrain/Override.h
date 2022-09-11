#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include "IOUtils.h"
#include "BasicPE.h"
#include "Loader.h"


#define SLEEP_TIME 2000

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
	bool ReplaceImage(const wchar_t* proc, const wchar_t* newImagePath, bool self);
	DWORD GetPID(const wchar_t* proc);

private:
	LPVOID ReplaceImage(HANDLE hProc, const File& target, BasicPE& pe);
};

