#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 9000
#define BUFFER_SIZE 4096

int main(void)
{
    WSADATA wsaData;
    int iResult;
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char buffer[BUFFER_SIZE];
    FILE* fp = NULL;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if(iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    // Create a listening socket
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(ListenSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set up the TCP listening socket
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces
    serverAddr.sin_port = htons(PORT);

    iResult = bind(ListenSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if(iResult == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    iResult = listen(ListenSocket, SOMAXCONN);
    if(iResult == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    printf("Server is listening on port %d...\n", PORT);

    // Accept a client connection
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if(ClientSocket == INVALID_SOCKET) {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    printf("Client connected.\n");

    // Close the listening socket (if only one client is expected)
    closesocket(ListenSocket);

    // Open a file to write the exfiltrated data (binary mode)
    fp = fopen("exfiltrated_video.raw", "wb");
    if(fp == NULL) {
        printf("Failed to open file for writing.\n");
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // Receive data in a loop and write it to the file.
    while(1) {
        iResult = recv(ClientSocket, buffer, BUFFER_SIZE, 0);
        if(iResult > 0) {
            fwrite(buffer, 1, iResult, fp);
            printf("Received %d bytes and wrote to file.\n", iResult);
        } else if(iResult == 0) {
            printf("Connection closing...\n");
            break;
        } else {
            printf("recv failed: %d\n", WSAGetLastError());
            break;
        }
    }

    fclose(fp);
    closesocket(ClientSocket);
    WSACleanup();
    printf("Server shutdown.\n");
    return 0;
}
