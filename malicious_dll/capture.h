#ifndef CAPTURE_H
#define CAPTURE_H

#include <mfidl.h>
#include <mfreadwrite.h>
#ifdef __cplusplus
extern "C" {
#endif

extern IMFSourceReader* g_pSourceReader;  // Make it global

BOOL InitializeCaptureSession();
VOID CleanupCaptureSession();

#ifdef __cplusplus
}
#endif
#endif
