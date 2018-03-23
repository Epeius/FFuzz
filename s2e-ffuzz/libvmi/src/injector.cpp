///
/// Copyright (C) 2015, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#include <stdio.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <vmi/PEFile.h>

using namespace vmi;

int main(int argc, char **argv)
{
    if (argc != 2) {
        llvm::outs() << "Usage: " << argv[0] << " pe_file";
        return -1;
    }

    std::string path(argv[1]);
    FileSystemFileProvider *fp = new FileSystemFileProvider(path);
    if (!fp->open(true)) {
        llvm::errs() << "Could not open " << path << "\n";
        return -1;
    }

    ExecutableFile *file = ExecutableFile::get(fp, false, 0);
    if (!file) {
        llvm::errs() << path << " is not a valid executable file\n";
        return -1;
    }

    PEFile *peFile = dynamic_cast<PEFile*>(file);
    if (!peFile) {
        llvm::errs() << "Only PE files are supported for now\n";
    }

    /* Create a dummy section */
    unsigned size = 0x12400;
    uint8_t *sec = new uint8_t[size];
    for (unsigned i = 0; i < size; ++i) {
        sec[i] = (uint8_t) i;
    }

    if (!peFile->appendSection(".inj", sec, size)) {
        llvm::errs() << "Could not append section\n";
    }

    delete [] sec;

    delete peFile;
    delete fp;

    return 0;
}
