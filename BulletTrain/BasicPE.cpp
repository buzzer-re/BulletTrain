#include "BasicPE.h"

bool BasicPE::ParseBuffer(BYTE* buff)
{
	pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buff);
	if (pDosHeader->e_magic != 0x5A4D) return false;

	pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(buff + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeader->OptionalHeader;
	pFileHeader = &pNtHeader->FileHeader;


    return true;
}
