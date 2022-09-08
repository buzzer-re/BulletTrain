#include "Override.h"
#include <iostream>

int main()
{
    int* p = NULL;
    Override overrider;
    overrider.ReplaceImage(L"BulletTrain.exe", L"C:\\Users\\Kurama\\source\\repos\\hook\\x64\\Debug\\hook.dll");
}
