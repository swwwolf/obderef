/*
* This code is licensed under the MIT license (MIT).
* Copyright © 2018  Vyacheslav Rusakoff (@swwwolf)
*/

#ifndef OBDEREF_OBDEREF_H_
#define OBDEREF_OBDEREF_H_

#include <cstdint>

// https://msdn.microsoft.com/ru-ru/library/windows/desktop/ms724509(v=vs.85).aspx
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    uint32_t Length;
    uint32_t CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

#define SystemCodeIntegrityInformation 0x0067

// Windows 10 RS3 (16299) only
#if defined(_WIN64)
    #define OBJECT_TO_OBJECT_HEADER_ADD(addr)   reinterpret_cast<uintptr_t>(reinterpret_cast<uint8_t*>(addr) + 0x30)
    #define EPROCESS_TO_PROTECTION(addr)        reinterpret_cast<uintptr_t>(reinterpret_cast<uint8_t*>(addr) + 0x6CA)
#else   // !_WIN64
    #define OBJECT_TO_OBJECT_HEADER_ADD(addr)   reinterpret_cast<uintptr_t>(reinterpret_cast<uint8_t*>(addr) + 0x18)
    #define EPROCESS_TO_PROTECTION(addr)        reinterpret_cast<uintptr_t>(reinterpret_cast<uint8_t*>(addr) + 0x2EE)
#endif  // _WIN64

#endif  // OBDEREF_OBDEREF_H_
