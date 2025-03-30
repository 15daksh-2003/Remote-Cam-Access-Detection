// File: RemoteCamAttack.c

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DLL_RELATIVE_PATH "..\\malicious_dll\\malicious_dll.dll" // Relative path from child process working dir
#define POLL_INTERVAL_MS 2000   // Parent process polling interval (2 seconds)
#define DEFAULT_RUNTIME 30      // Default runtime in seconds if not provided

// ======================================================================
// Function: ChildProcessMain
// Purpose:  This function is executed when the executable is launched with
//           the "-child" flag. It loads the malicious DLL, waits for the
//           specified runtime, unloads the DLL, and then exits.
// ======================================================================
int ChildProcessMain(int runtime)
{
    printf("[ChildProcess] Starting child process with runtime %d seconds.\n", runtime);

    // Load the malicious DLL from the relative path.
    HMODULE hDll = LoadLibrary(DLL_RELATIVE_PATH);
    if (hDll == NULL)
    {
        printf("[ChildProcess] Failed to load DLL from %s. Error: %d\n", DLL_RELATIVE_PATH, GetLastError());
        return 1;
    }
    printf("[ChildProcess] DLL loaded successfully.\n");

    // Allow the DLL to operate for the specified runtime duration.
    Sleep(runtime * 1000);

    // Unload the DLL to trigger its cleanup routines.
    if (!FreeLibrary(hDll))
    {
        printf("[ChildProcess] Failed to unload DLL. Error: %d\n", GetLastError());
    }
    else
    {
        printf("[ChildProcess] DLL unloaded successfully.\n");
    }

    printf("[ChildProcess] Exiting child process.\n");
    return 0;
}

// ======================================================================
// Function: ParentProcessMain
// Purpose:  This function is executed when the executable is launched as the
//           main process. It parses the command-line arguments, creates a child
//           process (passing along runtime parameters), and then monitors the
//           child process until termination.
// ======================================================================
int ParentProcessMain(int runtime)
{
    // Retrieve the full path of the current executable.
    char exePath[MAX_PATH];
    if (GetModuleFileName(NULL, exePath, MAX_PATH) == 0)
    {
        printf("[ParentProcess] Failed to get module file name. Error: %d\n", GetLastError());
        return 1;
    }

    // Construct the command-line for the child process.
    // The child process is the same executable but with the "-child" flag.
    char cmdLine[512];
    sprintf(cmdLine, "\"%s\" -child -runtime %d", exePath, runtime);

    printf("[ParentProcess] Creating child process with command: %s\n", cmdLine);

    // Set up structures for process creation.
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create the child process.
    if (!CreateProcess(NULL,       // No module name; use command line.
                       cmdLine,    // Command-line string.
                       NULL,       // Process handle not inheritable.
                       NULL,       // Thread handle not inheritable.
                       FALSE,      // Set handle inheritance to FALSE.
                       0,          // No creation flags.
                       NULL,       // Use parent's environment block.
                       NULL,       // Use parent's starting directory.
                       &si,        // Pointer to STARTUPINFO structure.
                       &pi))       // Pointer to PROCESS_INFORMATION structure.
    {
        printf("[ParentProcess] Failed to create child process. Error: %d\n", GetLastError());
        return 1;
    }
    printf("[ParentProcess] Child process created successfully. PID: %d\n", pi.dwProcessId);

    // Monitor the child process: check periodically if it has terminated.
    DWORD waitResult;
    while (1)
    {
        waitResult = WaitForSingleObject(pi.hProcess, POLL_INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0)
        {
            printf("[ParentProcess] Child process has terminated.\n");
            break;
        }
        else if (waitResult == WAIT_TIMEOUT)
        {
            printf("[ParentProcess] Child process (PID: %d) is still running...\n", pi.dwProcessId);
        }
        else
        {
            printf("[ParentProcess] WaitForSingleObject error: %d\n", GetLastError());
            break;
        }
    }

    // Clean up process handles.
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("[ParentProcess] Exiting parent process.\n");

    return 0;
}

// ======================================================================
// Function: main
// Purpose:  Entry point for RemoteCamAttack.exe. It checks for the "-child"
//           flag in the command-line arguments to determine whether to run as
//           the parent process (which creates a child) or as the child process
//           (which loads/unloads the DLL and simulates the attack).
// ======================================================================
int main(int argc, char *argv[])
{
    int isChild = 0;
    int runtime = DEFAULT_RUNTIME; // default runtime in seconds

    // Parse command-line arguments.
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-child") == 0)
        {
            isChild = 1;
        }
        else if (strcmp(argv[i], "-runtime") == 0 && i + 1 < argc)
        {
            runtime = atoi(argv[i + 1]);
            i++; // Skip the runtime value as it has been processed.
        }
    }

    // If the "-child" flag is present, run the child process routine.
    if (isChild)
    {
        return ChildProcessMain(runtime);
    }
    else
    {
        // Otherwise, run as the parent process.
        printf("[Main] Starting RemoteCamAttack as parent process.\n");
        return ParentProcessMain(runtime);
    }
}