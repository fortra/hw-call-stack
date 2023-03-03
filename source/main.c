
#include "main.h"
#include "syscalls.h"

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        PRINT_ERR("usage: %s <pid> <dll>", argv[0]);
        return -1;
    }

    PRINT("-- HW Call Stack --\n")

    HMODULE hLib = NULL;
    LPSTR dll_path = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ACCESS_MASK DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;

    // variables passed by reference must be stored on the heap
    PHANDLE ProcessHandle = intAlloc(sizeof(HANDLE));
    POBJECT_ATTRIBUTES ObjectAttributes = intAlloc(sizeof(OBJECT_ATTRIBUTES));
    PCLIENT_ID uPid = intAlloc(sizeof(CLIENT_ID));
    dll_path = intAlloc(MAX_PATH);
    strncpy(dll_path, argv[2], MAX_PATH);
    uPid->UniqueProcess = (HANDLE)(ULONG_PTR)atoi(argv[1]);
    uPid->UniqueThread = (HANDLE)0;
    InitializeObjectAttributes(
        ObjectAttributes,
        NULL,
        0,
        NULL,
        NULL);

    PRINT("calling NtOpenProcess...");
    status = _NtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        uPid);
    PRINT("status: 0x%lx", status);

    PRINT("\ncalling LoadLibraryA...");
    hLib = _LoadLibraryA(dll_path);
    PRINT("Kernel32.dll has been loaded at 0x%p", hLib);

    PRINT("\nBye!");

    intFree(ProcessHandle);
    intFree(ObjectAttributes);
    intFree(uPid);
    intFree(dll_path);

    return 0;
}
