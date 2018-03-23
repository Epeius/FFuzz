///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef _IMAGE_H_

#define _IMAGE_H_


#include <iostream>
#include <vector>

#include <s2e/S2EExecutionState.h>
#include "ModuleDescriptor.h"

namespace s2e {

/**
 *  This class models an executable image loaded in
 *  virtual memory.
 *  This is an abstract class which must be subclassed
 *  by actual implementation for Windows PE, Linux ELF, etc...
 */
struct IExecutableImage
{
public:



    virtual uint64_t GetBase() const = 0;
    virtual uint64_t GetImageBase() const = 0;
    virtual uint64_t GetImageSize() const = 0;
    virtual uint64_t GetEntryPoint() const = 0;
    virtual uint64_t GetRoundedImageSize() const = 0;

    virtual const Exports& GetExports(S2EExecutionState *s) = 0;
    virtual const Imports& GetImports(S2EExecutionState *s) = 0;

    virtual const ModuleSections &GetSections(S2EExecutionState *s) = 0;

    virtual void DumpInfo(std::ostream &os) const = 0;

};



}
#endif


