/*
* This code is licensed under the MIT license (MIT).
* Copyright © 2018  Vyacheslav Rusakoff (@swwwolf)
*/

#include <ntifs.h>
#include <ntintsafe.h>

#include "init.h"
#include "../include/control.h"

//////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
extern "C" {
#endif

    DRIVER_INITIALIZE DriverEntry;
    DRIVER_UNLOAD DriverUnload;

    _Dispatch_type_(IRP_MJ_CREATE)
    _Dispatch_type_(IRP_MJ_CLOSE)
    _Dispatch_type_(IRP_MJ_CLEANUP)
    DRIVER_DISPATCH DispatchSuccess;

    _Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
    DRIVER_DISPATCH DispatchControl;

    NTSTATUS CreateDevice(_In_ DRIVER_OBJECT* DriverObject);
    VOID DeleteDevice();
#ifdef __cplusplus
}
#endif
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(INIT, CreateDevice)

    #pragma alloc_text(PAGECODE, DriverUnload)
    #pragma alloc_text(PAGECODE, DeleteDevice)
#endif
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
PDEVICE_OBJECT g_DeviceObject = NULL;
PVOID g_Payload = NULL;

DECLARE_CONST_UNICODE_STRING(g_DeviceName, L"\\Device\\" DEVICE_NAME);
DECLARE_CONST_UNICODE_STRING(g_DeviceNameLink, L"\\DosDevices\\" DEVICE_NAME);
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchSuccess;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchSuccess;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchSuccess;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS status = CreateDevice(DriverObject);

    if ( !NT_SUCCESS(status) ) {
        return status;
    }

    g_Payload = ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE, POOL_TAG);

    if ( g_Payload != NULL ) {
#if defined(_WIN64)
        RtlFillMemoryUlonglong(g_Payload, PAGE_SIZE, INT64_MAX);

        // fill with predefined values for demonstration
        PULONGLONG Payload = (PULONGLONG)g_Payload;

        Payload[0] = (ULONGLONG)0x18825148b5000;
        Payload[1] = (ULONGLONG)0xb8828b5000;
        Payload[2] = (ULONGLONG)0x49000002e8889000;
        Payload[3] = (ULONGLONG)0x34f8518b481000;
        Payload[4] = (ULONGLONG)0x34077404fa9000;
        Payload[5] = (ULONGLONG)0x418b48edeb099000;
        Payload[6] = (ULONGLONG)0x358808949f03000;
        Payload[7] = (ULONGLONG)0x4890909090901000;
        Payload[8] = (ULONGLONG)0xc40000;
#else   // !_WIN64
        RtlFillMemoryUlong(g_Payload, PAGE_SIZE, INT32_MAX);    // don't care about 32-bit Windows
#endif  // _WIN64
    }

    return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
VOID DriverUnload(_In_ DRIVER_OBJECT* DriverObject) {
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if ( g_Payload != NULL ) {
        ExFreePoolWithTag(g_Payload, POOL_TAG);
        g_Payload = NULL;
    }

    DeleteDevice();
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS CreateDevice(_In_ DRIVER_OBJECT* DriverObject) {
    NTSTATUS status = IoCreateDevice(DriverObject,
                                     0,
                                     (PUNICODE_STRING)&g_DeviceName,
                                     FILE_DEVICE_UNKNOWN,
                                     0,
                                     FALSE,
                                     &g_DeviceObject);

    if ( !NT_SUCCESS(status) ) {
        DbgPrint("Unable to create device object\n");
        return status;
    }

    status = IoCreateSymbolicLink((PUNICODE_STRING)&g_DeviceNameLink, (PUNICODE_STRING)&g_DeviceName);

    if ( !NT_SUCCESS(status) ) {
        DbgPrint("Unable to create symbolic link\n");

        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;

        return status;
    }

    return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
VOID DeleteDevice() {
    PAGED_CODE();

    IoDeleteSymbolicLink((PUNICODE_STRING)&g_DeviceNameLink);

    if ( g_DeviceObject != NULL ) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS DispatchSuccess(_In_ _DEVICE_OBJECT* DeviceObject, _Inout_ _IRP* Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS DispatchControl(_In_ _DEVICE_OBJECT* DeviceObject, _Inout_ _IRP* Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION iosp = IoGetCurrentIrpStackLocation(Irp);

    switch ( iosp->Parameters.DeviceIoControl.IoControlCode ) {
        case IOCTL_OBDEREF_EXECUTE:
        {
            ULONG in_size = iosp->Parameters.DeviceIoControl.InputBufferLength;
            POBDEREF_CONTROL_STRUCT control = (POBDEREF_CONTROL_STRUCT)Irp->AssociatedIrp.SystemBuffer;

            if ( !ARGUMENT_PRESENT(control) || in_size != sizeof(*control) ) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID object = (PVOID)control->object;

            if ( ARGUMENT_PRESENT(object) ) {
                //DbgPrint("ObDereferenceObject object at: 0x%p\n", object);
                ObDereferenceObject(object);                            // decrement _some_ memory
            }

            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_OBDEREF_LEAK_PAYLOAD:
        {
            ULONG out_size = iosp->Parameters.DeviceIoControl.OutputBufferLength;

            if ( out_size != sizeof(g_Payload) ) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            *(PVOID*)(Irp->AssociatedIrp.SystemBuffer) = g_Payload;     // leak payload address
            Irp->IoStatus.Information = sizeof(g_Payload);

            status = STATUS_SUCCESS;
            break;
        }

        default:
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
//////////////////////////////////////////////////////////////////////////
