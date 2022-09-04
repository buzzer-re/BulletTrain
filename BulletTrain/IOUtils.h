#pragma once

#include <windows.h>

class File
{
public:
	File(const wchar_t* path);
	~File();

	BYTE* data;
	DWORD length;
};