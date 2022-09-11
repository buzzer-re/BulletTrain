#pragma once

#include <windows.h>
#include <iostream>


#define LOG(msg, should) \
	if (should) \
		std::printf("[+] %s [+]\n", msg);

#define LOG_ERROR(msg, should) \
	if (should) \
		std::printf("[-] %s [-]\n", msg);

class File
{
public:
	File(const wchar_t* path);
	~File();

	BYTE* data;
	DWORD length;
};