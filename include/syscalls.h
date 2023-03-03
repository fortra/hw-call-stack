#pragma once

#ifndef SW3_HEADER_H_
#define SW3_HEADER_H_

#include <windows.h>

#include "hw_breakpoint.h"
#include "spoof_callstack.h"
#include "dinvoke.h"
#include "utils.h"
#include "output.h"

#define NtOpenProcess_SW3_HASH 0x825c9bd0
#define LoadLibraryA_SW3_HASH 0xC52B9BB4

#ifdef _WIN64

typedef struct _SYSCALL_DATA
{
    PVOID full_stack_base;        // 0x00
    ULONG_PTR full_stack_size;    // 0x08
    PVOID full_stack_backup_addr; // 0x10
    PVOID fake_stack_heap_addr;   // 0x18
    ULONG_PTR fake_stack_size;    // 0x20
    PVOID fake_stack_target_addr; // 0x28
    PVOID fake_stack_rsp;         // 0x30
    PVOID fake_stack_rbp;         // 0x38
    PVOID canary_addr;            // 0x40
    union {
        PVOID syscall_addr;       // 0x48
        PVOID api_addr;           // 0x48
    };
    ULONG32 syscall_number;       // 0x50
    BOOL is_api_call;             // 0x54
    BOOL is_wow64;                // 0x58
    ULONG32 num_params;           // 0x5c
    ULONG_PTR params[10];         // 0x60+0x8*i
} SYSCALL_DATA, *PSYSCALL_DATA;

#else

typedef struct _SYSCALL_DATA
{
    PVOID full_stack_base;        // 0x00
    ULONG_PTR full_stack_size;    // 0x04
    PVOID full_stack_backup_addr; // 0x08
    PVOID fake_stack_heap_addr;   // 0x0c
    ULONG_PTR fake_stack_size;    // 0x10
    PVOID fake_stack_target_addr; // 0x14
    PVOID fake_stack_rsp;         // 0x18
    PVOID fake_stack_rbp;         // 0x1c
    PVOID canary_addr;            // 0x20
    union {
        PVOID syscall_addr;       // 0x24
        PVOID api_addr;           // 0x24
    };
    ULONG32 syscall_number;       // 0x28
    BOOL is_api_call;             // 0x2c
    BOOL is_wow64;                // 0x30
    ULONG32 num_params;           // 0x34
    ULONG_PTR params[10];         // 0x38+0x4*i
} SYSCALL_DATA, *PSYSCALL_DATA;

#endif

#define SW3_SEED 0x1337C0DE
#define SW3_ROL8(v) (v << 8 | v >> 24)
#define SW3_ROR8(v) (v >> 8 | v << 24)
#define SW3_ROX8(v) ((v % 2) ? SW3_ROL8(v) : SW3_ROR8(v))
#define SW3_MAX_ENTRIES 500
#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

#ifdef _M_IX86
 // x86 has conflicting types with these functions
 #define NtClose _NtClose
 #define NtQueryInformationProcess _NtQueryInformationProcess
 #define NtCreateFile _NtCreateFile
 #define NtQuerySystemInformation _NtQuerySystemInformation
 #define NtWaitForSingleObject _NtWaitForSingleObject
 #define NtQueryInformationFile _NtQueryInformationFile
#endif
// Typedefs are prefixed to avoid pollution.

typedef struct _SW3_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, *PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST
{
    DWORD Count;
    SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, *PSW3_SYSCALL_LIST;

typedef struct _SW3_PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} SW3_PEB_LDR_DATA, *PSW3_PEB_LDR_DATA;

typedef struct _SW3_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} SW3_LDR_DATA_TABLE_ENTRY, *PSW3_LDR_DATA_TABLE_ENTRY;

typedef struct _SW3_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PSW3_PEB_LDR_DATA Ldr;
} SW3_PEB, *PSW3_PEB;

DWORD SW3_HashSyscall(
    IN PCSTR FunctionName);

PVOID GetSyscallAddress(
    IN PVOID nt_api_address,
    IN ULONG32 size_of_ntapi);

BOOL SW3_PopulateSyscallList(VOID);

BOOL local_is_wow64(VOID);

void SyscallNotFound(VOID);

#if defined(__GNUC__)
DWORD SW3_GetSyscallNumber(IN DWORD FunctionHash) asm ("SW3_GetSyscallNumber");
PVOID SW3_GetSyscallAddress(IN DWORD FunctionHash) asm ("SW3_GetSyscallAddress");
#else
DWORD SW3_GetSyscallNumber(IN DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(IN DWORD FunctionHash);
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

NTSTATUS _NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext);

NTSTATUS _NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context);

NTSTATUS _NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PVOID ClientId OPTIONAL);

HMODULE _LoadLibraryA(
  IN LPCSTR lpLibFileName);

#endif
