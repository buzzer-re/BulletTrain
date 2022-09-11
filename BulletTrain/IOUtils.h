#pragma once

#include <windows.h>
#include <iostream>

class File
{
public:
	File(const wchar_t* path);
	~File();

	BYTE* data;
	DWORD length;
};