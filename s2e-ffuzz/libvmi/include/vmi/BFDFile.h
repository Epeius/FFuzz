///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef VMI_BFD_FILE_H

#define VMI_BFD_FILE_H

extern "C" {
#include <bfd.h>
}

#include <map>
#include <set>
#include <llvm/ADT/StringMap.h>
#include "ExecutableFile.h"

namespace vmi
{

class BFDFile : public ExecutableFile {

private:
    typedef std::map<SectionDescriptor, asection *> BFDSections;
    typedef llvm::StringMap<asymbol *> Symbols;
    typedef std::set<uint64_t> AddressSet;

    static bool s_bfdInited;
    bfd *m_bfd;
    asymbol **m_symbolTable;
    long m_symbolCount;

    uint64_t m_imageBase;
    BFDSections m_sections;
    Sections m_sections2;
    AddressSet m_invalidAddresses;
    Symbols m_symbols;

    static void initSections(bfd *abfd, asection *sect, void *obj);
    bool initialize(const std::string &format);
    asection *getSection(uint64_t va, unsigned size) const;


    static void *open_func(struct bfd *nbfd, void *open_closure);
    static file_ptr pread_func(struct bfd *nbfd, void *stream, void *buf, file_ptr nbytes, file_ptr offset);
    static int close_func(struct bfd *nbfd, void *stream);
    static int stat_func(struct bfd *abfd, void *stream, struct stat *sb);

protected:
    BFDFile(FileProvider *file, bool loaded, uint64_t loadAddress);

public:

    static BFDFile* get(FileProvider *file, bool loaded, uint64_t loadAddress);

    virtual ~BFDFile();

    virtual std::string getModuleName() const;
    virtual uint64_t getImageBase() const;
    virtual uint64_t getImageSize() const;
    virtual uint64_t getEntryPoint() const;
    virtual bool getSymbolAddress(const std::string &name, uint64_t *address);
    virtual bool getSourceInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function);
    virtual unsigned getPointerSize() const {
        assert(false && "Not implemented");

        // Control should never reach here
        abort();
    }

    const Sections& getSections() const {
        return m_sections2;
    }
};

}

#endif
