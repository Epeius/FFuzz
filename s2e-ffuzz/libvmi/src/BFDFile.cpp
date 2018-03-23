///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <vmi/BFDFile.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FileSystem.h>

namespace vmi {

bool BFDFile::s_bfdInited = false;

BFDFile::BFDFile(FileProvider *file, bool loaded, uint64_t loadAddress):ExecutableFile(file, loaded, loadAddress)
{
    m_bfd = NULL;
    m_symbolTable = NULL;
}

BFDFile::~BFDFile()
{

}

void *BFDFile::open_func(struct bfd *nbfd, void *open_closure)
{
    BFDFile *bfdptr = static_cast<BFDFile*>(open_closure);
    return bfdptr->m_file;
}

file_ptr BFDFile::pread_func(struct bfd *nbfd, void *stream, void *buf, file_ptr nbytes, file_ptr offset)
{
    FileProvider *file = static_cast<FileProvider*>(stream);
    ssize_t ret = file->read(buf, nbytes, offset);
    if (ret < 0) {
        bfd_set_error(bfd_error_on_input);
    }
    return ret;
}

int BFDFile::close_func(struct bfd *nbfd, void *stream)
{
    return 0;
}

int BFDFile::stat_func(struct bfd *abfd, void *stream, struct stat *sb)
{
    FileProvider *file = static_cast<FileProvider*>(stream);
    return file->stat(sb);
}

void BFDFile::initSections(bfd *abfd, asection *sect, void *obj)
{
    BFDFile *bfdptr = static_cast<BFDFile*>(obj);

    SectionDescriptor s;
    s.start = sect->vma;
    s.size = sect->size;

    //Deal with relocations
    if (bfd_get_section_flags(abfd, sect) & SEC_RELOC) {
        long reloc_size = bfd_get_reloc_upper_bound(bfdptr->m_bfd, sect);
        if (reloc_size > 0) {
            arelent **relent = (arelent**)malloc (reloc_size);
            long res = bfd_canonicalize_reloc(abfd, sect, relent, bfdptr->m_symbolTable);
            if (res < 0) {
                free(relent);
            }
        }
    }

    bfdptr->m_sections[s] = sect;
}


bool BFDFile::initialize(const std::string &format)
{
    if (!s_bfdInited) {
        bfd_init();
        s_bfdInited = true;
    }

    if (m_bfd) {
        return true;
    }

    const char *bfdFormat = NULL;
    if (format.size() > 0) {
        bfdFormat = format.c_str();
    }

    //m_bfd = bfd_fopen(m_file.str().c_str(), bfdFormat, "rw", -1);

    m_bfd = bfd_openr_iovec(m_file->getName(), bfdFormat, open_func, this, pread_func, close_func, stat_func);

    if (!m_bfd) {
        llvm::errs() << "Could not open bfd file " << m_file->getName() << " - ";
        llvm::errs() << bfd_errmsg(bfd_get_error()) << '\n';
        return false;
    }

    if (!bfd_check_format (m_bfd, bfd_object)) {
        llvm::errs() << m_file->getName() << " has invalid format " << '\n';
        bfd_close(m_bfd);
        m_bfd = NULL;
        return false;
    }

    long storage_needed = bfd_get_symtab_upper_bound (m_bfd);
    long number_of_symbols;

    if (storage_needed < 0) {
        llvm::errs() << "Failed to determine needed storage" << '\n';
        bfd_close(m_bfd);
        m_bfd = NULL;
        return false;
    }

    m_symbolTable = (asymbol**)malloc (storage_needed);
    number_of_symbols = bfd_canonicalize_symtab (m_bfd, m_symbolTable);
    if (number_of_symbols < 0) {
        llvm::errs() << "Failed to determine number of symbols" << '\n';
        bfd_close(m_bfd);
        m_bfd = NULL;
        return false;
    }

    m_symbolCount = number_of_symbols;
    for (unsigned i=0; i<m_symbolCount; ++i) {
        m_symbols[m_symbolTable[i]->name] = m_symbolTable[i];
    }

    bfd_map_over_sections(m_bfd, initSections, this);

    //Compute image base
    //XXX: Make sure it is correct
    BFDSections::const_iterator it;
    uint64_t vma=(uint64_t)-1;
    for (it = m_sections.begin(); it != m_sections.end(); ++it) {
        asection *section = (*it).second;
        if (section->vma && (section->vma < vma)) {
            vma = section->vma;
        }
        m_sections2.push_back((*it).first);
    }
    assert(vma);
    m_imageBase = vma & (uint64_t)~0xFFF;

    return true;
}


BFDFile* BFDFile::get(FileProvider *file, bool loaded, uint64_t loadAddress)
{
    BFDFile *ret = new BFDFile(file, loaded, loadAddress);
    if (!ret->initialize("")) {
        delete ret;
        ret = NULL;
    }
    return ret;
}

asection *BFDFile::getSection(uint64_t va, unsigned size) const
{
    SectionDescriptor s;
    s.start = va;
    s.size = size;

    BFDSections::const_iterator it = m_sections.find(s);
    if (it == m_sections.end()) {
        return NULL;
    }

    assert((*it).second->vma <= va);

    return (*it).second;
}

std::string BFDFile::getModuleName() const
{
    return llvm::sys::path::filename(std::string(m_file->getName()));
}

uint64_t BFDFile::getImageBase() const
{
    return m_imageBase;
}

uint64_t BFDFile::getImageSize() const
{
    return bfd_get_size(m_bfd);
}

uint64_t BFDFile::getEntryPoint() const
{
    return m_bfd->start_address;
}

bool BFDFile::getSymbolAddress(const std::string &name, uint64_t *address)
{
    Symbols::const_iterator it = m_symbols.find(name);
    if (it == m_symbols.end()) {
        return false;
    }

    *address = bfd_asymbol_value((*it).second);
    return true;
}

bool BFDFile::getSourceInfo(uint64_t va, std::string &source, uint64_t &line, std::string &function)
{
    if (m_invalidAddresses.find(va) != m_invalidAddresses.end()) {
        return false;
    }
    asection *section = getSection(va, 1);
    if (!section) {
        m_invalidAddresses.insert(va);
        return false;
    }

    const char *filename;
    const char *funcname;
    unsigned int sourceline;

    if (bfd_find_nearest_line(m_bfd, section, m_symbolTable, va - section->vma,
        &filename, &funcname, &sourceline)) {

        source = filename ? filename : "<unknown source>" ;
        line = sourceline;
        function = funcname ? funcname:"<unknown function>";

        if (!filename && !line && !funcname) {
            return false;
        }
        return true;

    }

    return false;
}

}
