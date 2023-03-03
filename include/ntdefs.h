#pragma once

#include <windows.h>
#include <winternl.h>

#define NTDLL_DLL L"ntdll.dll"
#define KERNEL32_DLL L"Kernel32.dll"
#define KERNELBASE_DLL L"KernelBase.dll"

#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )

#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
