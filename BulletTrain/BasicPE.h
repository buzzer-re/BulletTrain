#pragma once
#include <Windows.h>

class BasicPE
{

public:
	bool ParseBuffer(BYTE* buff);
	void PrintImports() const;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_FILE_HEADER	pFileHeader;

private:
	ULONG_PTR pBuff;
};
