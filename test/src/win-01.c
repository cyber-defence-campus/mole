#include <windows.h>
#include <stdio.h>

typedef struct _MY_STRUCT {
    PBYTE ValueInfo;
} MY_STRUCT, *PMY_STRUCT;

int main() {
    PMY_STRUCT myStruct = NULL;
    HKEY hKey = NULL;
    LONG result;
    DWORD dataSize = 512;
    const wchar_t* subKey = L"SOFTWARE\\Example";
    const wchar_t* valueName = L"MyValue";

    // Open the registry key
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        printf("Failed to open key: %ld\n", result);
        return 1;
    }

    // Allocate the structure
    myStruct = (PMY_STRUCT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MY_STRUCT));
    if (!myStruct) {
        RegCloseKey(hKey);
        return 1;
    }

    // Allocate the field
    myStruct->ValueInfo = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataSize);
    if (!myStruct->ValueInfo) {
        HeapFree(GetProcessHeap(), 0, myStruct);
        RegCloseKey(hKey);
        return 1;
    }

    // Query the value
    result = RegQueryValueExW(hKey, valueName, NULL, NULL, myStruct->ValueInfo, &dataSize);
    if (result == ERROR_SUCCESS) {
        printf("Value queried successfully.\n");
    } else {
        printf("Failed to query value: %ld\n", result);
    }

    // Cleanup
    if (myStruct->ValueInfo)
        HeapFree(GetProcessHeap(), 0, myStruct->ValueInfo);
    if (myStruct)
        HeapFree(GetProcessHeap(), 0, myStruct);
    if (hKey)
        RegCloseKey(hKey);

    return 0;
}
