#include <tchar.h>
#include "Override.h"

#include <iostream>
#include <filesystem>


namespace fs = std::filesystem;

wchar_t* GetExecName(const wchar_t* full_path)
{

}

int _tmain(int argc, _TCHAR** argv)
{
    Override overrider;
    
    if (argc < 2) {
        std::wprintf(L"Usage: %s PE_PATH PROCESS_TO_INJECT (Optional)\n", argv[0]);
        return EXIT_FAILURE;
    }

    bool self_injection = argc == 2;
   
    const wchar_t* pe_inject = argv[1];
    // If no process was supplied, inject in itself
    std::wstring target_inject = self_injection ? fs::path(argv[0]).filename() : fs::path(argv[2]).filename();
  
    std::wprintf(L"[+] Loading %s [+]\n", pe_inject);

    if (overrider.ReplaceImage(target_inject.c_str(), pe_inject, self_injection)) {
        std::wprintf(L"[+] %s injected sucessfully! [+]\n", pe_inject);
        return EXIT_SUCCESS;
    } 

    std::wprintf(L"[+] Unable to inject %s! [+]\n", pe_inject);
    return EXIT_FAILURE;
}

