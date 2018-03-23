///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include "FileProvider.h"
#include <vmi/WindowsCrashDumpGenerator.h>

#ifndef VMI_WINKERN_DUMPFILE

#define VMI_WINKERN_DUMPFILE

namespace vmi {
namespace windows {

class WinKernDumpFile : public FileProvider {
private:
    FileProvider *m_file;
    unsigned m_pointerSize;

    DUMP_HEADER64 Header64;
    DUMP_HEADER32 Header32;

    bool initializePointerSize();


public:

    WinKernDumpFile(FileProvider *file) : m_file(file) {}
    virtual ~WinKernDumpFile();

    virtual bool open(bool writable);
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset);
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset);
    virtual int stat(struct stat *buf);
    virtual const char *getName() const;

    unsigned getPointerSize() const {
        return m_pointerSize;
    }

    bool getHeader32(DUMP_HEADER32 &Header) const {
        if (m_pointerSize != 4) {
            return false;
        }
        Header = Header32;
        return true;
    }

    bool getHeader64(DUMP_HEADER64 &Header) const {
        if (m_pointerSize != 8) {
            return false;
        }
        Header = Header64;
        return true;
    }
};


}
}

#endif
