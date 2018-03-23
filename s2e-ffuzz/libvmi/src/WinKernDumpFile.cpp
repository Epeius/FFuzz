///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <vmi/WinKernDumpFile.h>
#include <iostream>

namespace vmi {
namespace windows {

WinKernDumpFile::~WinKernDumpFile()
{

}

bool WinKernDumpFile::initializePointerSize()
{
    //Determine 32-bits/64-bits
    uint32_t signature[2];

    if (!m_file->readb(signature, sizeof(signature), 0)) {
        return false;
    }

    if (signature[0] != DUMP_HDR_SIGNATURE) {
        return false;
    }

    switch (signature[1]) {
        case DUMP_HDR_DUMPSIGNATURE:
            m_pointerSize = 4;
            break;
        case DUMP_HDR_DUMPSIGNATURE64:
            m_pointerSize = 8;
            break;
        default:
            return false;
    }

   return true;
}

bool WinKernDumpFile::open(bool writable)
{
    if (writable) {
        return false;
    }

    if (!initializePointerSize()) {
        return false;
    }

    bool result;

    if (m_pointerSize == 8) {
        result = m_file->readb(&Header64, sizeof(Header64), 0);
    } else {
        result = m_file->readb(&Header32, sizeof(Header32), 0);
    }

    return result;
}

ssize_t WinKernDumpFile::read(void *buffer, size_t nbyte, off64_t offset)
{
    return -1;
}

ssize_t WinKernDumpFile::write(const void *buffer, size_t nbyte, off64_t offset)
{
    return -1;
}

int WinKernDumpFile::stat(struct stat *buf)
{
    return -1;
}

const char *WinKernDumpFile::getName() const
{
    return m_file->getName();
}

}
}
