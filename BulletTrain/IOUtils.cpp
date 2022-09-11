#include "IOUtils.h"

// Just a simple code to read and free some file bytes

File::File(const wchar_t* path)
    : length(0), data(nullptr)
{
    if (!GetFileAttributes(path)) return;

    HANDLE hFile = CreateFile(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
    if (!hFile || hFile == INVALID_HANDLE_VALUE) return;

    this->length = GetFileSize(hFile, NULL);
    if (this->length == INVALID_FILE_SIZE) return;

    this->data = new BYTE[this->length];

    if (!this->data) return;

    DWORD bytesRead;
    if (!ReadFile(hFile, (LPVOID)this->data, this->length, &bytesRead, NULL))
    {
        delete[] this->data;
        this->length = 0;
    }

    CloseHandle(hFile);
}

File::~File()
{
    if (data != nullptr)
    {
        delete[] data;
    }
}
