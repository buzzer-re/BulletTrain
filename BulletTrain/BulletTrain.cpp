#include "Override.h"
#include <iostream>


int main()
{
    int* p = NULL;
    Override overrider;
    overrider.ReplaceImage(L"BulletTrain.exe", L"C:\\Program Files\\7-Zip\\7z.exe", true);
}
