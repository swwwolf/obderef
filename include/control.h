/*
* This code is licensed under the MIT license (MIT).
* Copyright © 2018  Vyacheslav Rusakoff (@swwwolf)
*/

#ifndef INCLUDE_CONTROL_H_
#define INCLUDE_CONTROL_H_

#define DEVICE_NAME             L"obderef"
#define DOS_DEVICE_NAME         L"\\\\.\\" DEVICE_NAME

#define IOCTL_OBDEREF_EXECUTE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBDEREF_LEAK_PAYLOAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _OBDEREF_CONTROL_STRUCT {
    uintptr_t object;
} OBDEREF_CONTROL_STRUCT, *POBDEREF_CONTROL_STRUCT;

#endif  // INCLUDE_CONTROL_H_
