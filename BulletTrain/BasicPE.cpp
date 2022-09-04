#include "BasicPE.h"
#include <iostream>

bool BasicPE::ParseBuffer(BYTE* buff)
{

	pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buff);
	if (pDosHeader->e_magic != 0x5A4D) return false;

	pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(buff + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeader->OptionalHeader;
	pFileHeader = &pNtHeader->FileHeader;


    return true;
}


// Simple function that just print all the imported DLLS and functions
void BasicPE::PrintImports() const
{
	IMAGE_DATA_DIRECTORY* importDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	PIMAGE_IMPORT_DESCRIPTOR impDescritor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((DWORD_PTR) pDosHeader + importDirectory->VirtualAddress);

}
