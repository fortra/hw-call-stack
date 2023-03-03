#pragma once

#include "ntdefs.h"

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define RVA(type, base_addr, rva) (type)(ULONG_PTR)((ULONG_PTR) base_addr + rva)

#ifdef _WIN64
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

