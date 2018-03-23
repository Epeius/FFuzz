#include <ntddk.h>

#include "s2e.h"
#include "hook.h"

typedef struct _MODULE_ENTRY
{
    LIST_ENTRY ListEntry;
    DWORD  unknown[4];
    PVOID  Base;
    PVOID  DriverStart;
    DWORD  unk1;
    UNICODE_STRING DriverPath;
    UNICODE_STRING DriverName;
}  MODULE_ENTRY, *PMODULE_ENTRY;

VOID ReloadImports(PDRIVER_OBJECT DriverObject)
{
    PLIST_ENTRY ListHead;
    PLIST_ENTRY Item;

    MODULE_ENTRY *ModuleEntry = DriverObject->DriverSection;
    if (!ModuleEntry) {
        S2EMessage("ModuleEntry is NULL\n");
        return;
    }

    //XXX: The real head is PsLoadedModuleList...
    ListHead = &ModuleEntry->ListEntry;
    Item = ListHead->Flink;

    while (Item != ListHead) {
        MODULE_ENTRY *Entry = CONTAINING_RECORD(Item, MODULE_ENTRY, ListEntry);
        if (Entry->DriverStart && Entry->Base) {
            ANSI_STRING DriverName;
            RtlUnicodeStringToAnsiString(&DriverName, &Entry->DriverName, TRUE);
            S2EMessageFmt("Scanning %s (DriverStart=%#x Base=%#x)", DriverName.Buffer, Entry->DriverStart, Entry->Base);
            RtlFreeAnsiString(&DriverName);
        }
        Item = Item->Flink;
    }
}

static const MODULE_ENTRY *FindModule(PDRIVER_OBJECT DriverObject, PUNICODE_STRING ModuleToFind)
{
    PLIST_ENTRY ListHead;
    PLIST_ENTRY Item;

    MODULE_ENTRY *ModuleEntry = DriverObject->DriverSection;
    if (!ModuleEntry) {
        S2EMessage("ModuleEntry is NULL\n");
        return NULL;
    }

    //XXX: The real head is PsLoadedModuleList...
    ListHead = &ModuleEntry->ListEntry;
    Item = ListHead->Flink;

    while (Item != ListHead) {
        MODULE_ENTRY *Entry = CONTAINING_RECORD(Item, MODULE_ENTRY, ListEntry);
        if (Entry->DriverStart && Entry->Base) {
            ANSI_STRING DriverName;
            RtlUnicodeStringToAnsiString(&DriverName, &Entry->DriverName, TRUE);
            S2EMessageFmt("Scanning %s (DriverStart=%#x Base=%#x)", DriverName.Buffer, Entry->DriverStart, Entry->Base);

            if (RtlEqualUnicodeString(&Entry->DriverName, ModuleToFind, TRUE)) {
                return Entry;
            }

            RtlFreeAnsiString(&DriverName);
        }
        Item = Item->Flink;
    }

    return NULL;
}

NTSYSAPI PIMAGE_NT_HEADERS NTAPI
RtlImageNtHeader(IN PVOID ModuleAddress);

NTSYSAPI PVOID
RtlImageDirectoryEntryToData(
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size
);

typedef UINT16 WORD;
typedef UINT8 BYTE;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;


typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

typedef struct _IMAGE_IMPORT_DESCRIPTOR32 {
    union {
        UINT32 Characteristics; // 0 for terminating null import descriptor
        UINT32 OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    UINT32 TimeDateStamp; // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    UINT32 ForwarderChain; // -1 if no forwarders
    UINT32 Name;
    UINT32 FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR32, *PIMAGE_IMPORT_DESCRIPTOR32;

static VOID ScanImportDirectory(const MODULE_ENTRY *Module)
{
    PIMAGE_NT_HEADERS Header;
    PIMAGE_DATA_DIRECTORY ImportDirectory;
    PIMAGE_IMPORT_DESCRIPTOR32 Imports;
    unsigned i;

    Header = RtlImageNtHeader(Module->Base);
    if (!Header) {
        return;
    }

    S2EMessageFmt("Found NT image header @%#x", Header);

    for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        S2EMessageFmt("Directory %d @%#x of size %d", i, Header->OptionalHeader.DataDirectory[i].VirtualAddress,
                      Header->OptionalHeader.DataDirectory[i].Size);
    }

    ImportDirectory = (PIMAGE_DATA_DIRECTORY)
                      &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (!ImportDirectory->VirtualAddress) {
        S2EMessageFmt("No import directory");
        return;
    }

    Imports = (PIMAGE_IMPORT_DESCRIPTOR32)
             ((UINT_PTR)Module->Base + ImportDirectory->VirtualAddress);

    S2EMessageFmt("Found import directory @%#x of size %d", Imports, ImportDirectory->Size);

    ProbeForRead(Imports, ImportDirectory->Size, 1);
    for (i = 0; i < ImportDirectory->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR32); ++i) {

        if (!Imports[i].Name) {
            continue;
        }

        S2EMessageFmt("  Imported %s", (PCHAR)Module->Base + Imports[i].Name);
    }


}

/** Page in the import directory so that S2E plugins can read it. */
VOID ReloadModuleImports(PDRIVER_OBJECT DriverObject, PCSTR DriverName)
{
    ANSI_STRING DriverToFindAnsi;
    UNICODE_STRING DriverToFind;
    const MODULE_ENTRY *Module;

    RtlInitAnsiString(&DriverToFindAnsi, DriverName);
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&DriverToFind, &DriverToFindAnsi, TRUE))) {
        S2EMessageFmt("Failed to convert string to unicode\n", DriverName);
        goto err0;
    }

    Module = FindModule(DriverObject, &DriverToFind);
    if (!Module) {
        S2EMessageFmt("Could not find module %s\n", DriverName);
        goto err1;
    }

    try {
        ScanImportDirectory(Module);
    }  except (EXCEPTION_EXECUTE_HANDLER) {
        S2EMessageFmt("Exception while scanning import table\n");
    }

err1:
    RtlFreeUnicodeString(&DriverToFind);
err0:
    return;
}
