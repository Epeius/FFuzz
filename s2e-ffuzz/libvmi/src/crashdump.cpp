///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#include <stdio.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <vmi/WinKernDumpFile.h>
#include <vmi/ntddk.h>

using namespace vmi;
using namespace vmi::windows;

static void printUsage(const char *progName)
{
    fprintf(stderr, "Usage: %s memory.dmp\n", progName);
}


static void dumpContext(const CONTEXT64 &Context)
{
    std::cout
        << "CS:      0x" << std::hex << Context.SegCs << "\n"
        << "DS:      0x" << std::hex << Context.SegDs << "\n"
        << "ES:      0x" << std::hex << Context.SegEs << "\n"
        << "FS:      0x" << std::hex << Context.SegFs << "\n"
        << "GS:      0x" << std::hex << Context.SegGs << "\n"
        << "SS:      0x" << std::hex << Context.SegSs << "\n"
        << "EFLAGS:  0x" << std::hex << Context.EFlags << "\n"
        << "RAX:     0x" << std::hex << Context.Rax << "\n"
        << "RCX:     0x" << std::hex << Context.Rcx << "\n"
        << "RDX:     0x" << std::hex << Context.Rdx << "\n"
        << "RBX:     0x" << std::hex << Context.Rbx << "\n"
        << "RBP:     0x" << std::hex << Context.Rbp << "\n"
        << "RSP:     0x" << std::hex << Context.Rsp << "\n"
        << "RSI:     0x" << std::hex << Context.Rdi << "\n"
        << "RDI:     0x" << std::hex << Context.Rdi << "\n";
}

static void dumpContext(const CONTEXT32 &Context)
{
    std::cout
        << "CS:      0x" << std::hex << Context.SegCs << "\n"
        << "DS:      0x" << std::hex << Context.SegDs << "\n"
        << "ES:      0x" << std::hex << Context.SegEs << "\n"
        << "FS:      0x" << std::hex << Context.SegFs << "\n"
        << "GS:      0x" << std::hex << Context.SegGs << "\n"
        << "SS:      0x" << std::hex << Context.SegSs << "\n"
        << "EFLAGS:  0x" << std::hex << Context.EFlags << "\n"
        << "EAX:     0x" << std::hex << Context.Eax << "\n"
        << "ECX:     0x" << std::hex << Context.Ecx << "\n"
        << "EDX:     0x" << std::hex << Context.Edx << "\n"
        << "EBX:     0x" << std::hex << Context.Ebx << "\n"
        << "EBP:     0x" << std::hex << Context.Ebp << "\n"
        << "ESP:     0x" << std::hex << Context.Esp << "\n"
        << "ESI:     0x" << std::hex << Context.Edi << "\n"
        << "EDI:     0x" << std::hex << Context.Edi << "\n";
}

template <typename T>
static void dumpHeader(const T &Header)
{
    std::cout
            << "sizof(Header):      0x" << std::hex << sizeof(Header) << "\n"
            << "MajorVersion:       0x" << std::hex << Header.MajorVersion << "\n"
            << "MinorVersion:       0x" << std::hex << Header.MinorVersion << "\n"
            << "DirectoryTableBase: 0x" << std::hex << Header.DirectoryTableBase << "\n"
            << "PfnDataBase:        0x" << std::hex << Header.PfnDataBase << "\n"
            << "PsLoadedModuleList: 0x" << std::hex << Header.PsLoadedModuleList << "\n"
            << "PsActiveProcessHead:0x" << std::hex << Header.PsActiveProcessHead << "\n\n";

    std::cout
            << "MachineImageType:   0x" << std::hex << Header.MachineImageType << "\n"
            << "NumberProcessors:   0x" << std::hex << Header.NumberProcessors << "\n"
            << "BugCheckCode:       0x" << std::hex << Header.BugCheckCode << "\n"
            << "BugCheckParameter1: 0x" << std::hex << Header.BugCheckParameter1 << "\n"
            << "BugCheckParameter2: 0x" << std::hex << Header.BugCheckParameter2 << "\n"
            << "BugCheckParameter3: 0x" << std::hex << Header.BugCheckParameter3 << "\n"
            << "BugCheckParameter4: 0x" << std::hex << Header.BugCheckParameter4 << "\n\n";

    std::cout
            << "KdDebuggerDataBlock:0x" << std::hex << Header.KdDebuggerDataBlock << "\n\n";

    std::cout
            << "&Header.PhysicalMemoryBlock:    0x" << std::hex << offsetof(T, PhysicalMemoryBlock) << "\n"
            << "NumberOfRuns:       0x" << std::hex << Header.PhysicalMemoryBlock.NumberOfRuns << "\n"
            << "NumberOfPages:      0x" << std::hex << Header.PhysicalMemoryBlock.NumberOfPages << "\n";

    for (unsigned i = 0; i < Header.PhysicalMemoryBlock.NumberOfRuns; ++i) {
        std::cout << "Run " << i
                << " BasePage: " << Header.PhysicalMemoryBlock.Run[i].BasePage
                << " PageCount: " << Header.PhysicalMemoryBlock.Run[i].PageCount << "\n";
    }

    std::cout
            << "sizeof Context:     0x" << std::hex << sizeof(Header.Context) << "\n"
            << "&Header.Context:    0x" << std::hex << offsetof(T, Context) << "\n";

    dumpContext(Header.Context);


    std::cout
            << "ExceptionRecord:    0x" << std::hex << offsetof(T, ExceptionRecord) << "\n"
            << "ExceptionCode:      0x" << std::hex << Header.ExceptionRecord.ExceptionCode << "\n"
            << "ExceptionFlags:     0x" << std::hex << Header.ExceptionRecord.ExceptionFlags << "\n"
            << "ExceptionRecord:    0x" << std::hex << Header.ExceptionRecord.ExceptionRecord << "\n"
            << "ExceptionAddress:   0x" << std::hex << Header.ExceptionRecord.ExceptionAddress << "\n"
            << "NumberParameters:   0x" << std::hex << Header.ExceptionRecord.NumberParameters << "\n\n";

    std::cout
            << "&DumpType:          0x" << std::hex << offsetof(T, DumpType) << "\n"
            << "DumpType:           0x" << std::hex << Header.DumpType << "\n"
            << "RequiredDumpSpace:  0x" << std::hex << Header.RequiredDumpSpace << "\n"
            << "SystemTime:         0x" << std::hex << Header.SystemTime << "\n"
            << "SystemUpTime:       0x" << std::hex << Header.SystemUpTime << "\n"
            //<< "MiniDumpFields:          0x" << std::hex << Header.MiniDumpFields << "\n"
            << "SecondaryDataState: 0x" << std::hex << Header.SecondaryDataState << "\n"
            << "ProductType:        0x" << std::hex << Header.ProductType << "\n"
            << "SuiteMask:          0x" << std::hex << Header.SuiteMask << "\n";
            //<< "WriterStatus:            0x" << std::hex << Header.WriterStatus << "\n"
            //<< "KdSecondaryVersion:      0x" << std::hex << Header.KdSecondaryVersion << "\n";

}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printUsage(argv[0]);
        return -1;
    }

    std::string path(argv[1]);
    FileSystemFileProvider *fp = new FileSystemFileProvider(path);
    if (!fp->open(false)) {
        llvm::errs() << "Could not open " << path << "\n";
        return -1;
    }

    WinKernDumpFile dump(fp);
    if (!dump.open(false)) {
        llvm::errs() << "Could not initialize crash dump " << path << "\n";
        goto err1;
    }

    if (dump.getPointerSize() == 4) {
        DUMP_HEADER32 Header;
        dump.getHeader32(Header);
        dumpHeader(Header);
    } else {
        DUMP_HEADER64 Header;
        dump.getHeader64(Header);
        dumpHeader(Header);
    }

    err1: delete fp;

    return 0;
}
