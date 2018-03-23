///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <vmi/BFDFile.h>
#include <vmi/PEFile.h>
#include <vmi/CGCFile.h>

namespace vmi {

ExecutableFile::ExecutableFile(FileProvider *file, bool loaded, uint64_t loadAddress) {
    m_file = file;
    m_loaded = loaded;
    m_loadAddress = loadAddress;
}

ExecutableFile::~ExecutableFile()
{

}

ExecutableFile* ExecutableFile::get(FileProvider *file, bool loaded, uint64_t loadAddress)
{
    ExecutableFile *ret;

    ret = PEFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = CGCFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = BFDFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    return NULL;
}

}
