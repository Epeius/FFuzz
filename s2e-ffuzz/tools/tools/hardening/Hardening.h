/*
 * Copyright (c) 2015, CodeTickler, Inc
 * All rights reserved.
 *
 * Proprietary and confidential
 */


#ifndef _HARDENING_H_

#define _HARDENING_H_

#include <vmi/ExecutableFile.h>
#include <vmi/PEFile.h>
#include <vmi/FileProvider.h>
#include "lib/Utils/Log.h"

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>

namespace s2etools {

class Hardening {
    static LogKey TAG;

    std::string m_inputBinaryPath;
    vmi::PEFile *m_inputBinary;
    vmi::FileSystemFileProvider *m_fp;

    uint8_t *assemble(const std::string &assembly, unsigned *size);
    uint64_t getImportedFunction(const std::string &dll, const std::string &function);

public:
    Hardening(const std::string &inputBinaryPath) :
            m_inputBinaryPath(inputBinaryPath)
    {
        m_inputBinary = NULL;
        m_fp = NULL;
    }

    ~Hardening();

    bool initialize();
    bool harden(uint64_t pc);
};

}

#endif
