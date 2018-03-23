#include <ntddk.h>
#include "hook.h"

NTSTATUS DriverEntryHook(IN PDRIVER_OBJECT DriverObject,
                         IN PUNICODE_STRING RegistryPath,
                         IN DRIVER_INITIALIZE Original);


NTSTATUS DriverEntryHook(IN PDRIVER_OBJECT DriverObject,
                         IN PUNICODE_STRING RegistryPath,
                         IN DRIVER_INITIALIZE Original)
{
    return Original(DriverObject, RegistryPath);
}
