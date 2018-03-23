/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include "BFDInterface.h"
#include "Binary.h"

#include "Pe.h"
#include "Macho.h"

#include <stdlib.h>
#include <cassert>

#include <algorithm>
#include <iostream>
#include <vector>

namespace s2etools {

uint64_t RelocationEntry::getVirtualAddress() const {
    return virtualAddress;
}

unsigned RelocationEntry::getSize() const {
    return size;
}

uint64_t RelocationEntry::getOriginalValue() const {
    return originalValue;
}

uint64_t RelocationEntry::getTargetValue() const {
    return targetValue;
}

std::string RelocationEntry::getSymbolName() const {
    return symbolName;
}

uint64_t RelocationEntry::getSymbolBase() const {
    return symbolBase;
}

unsigned RelocationEntry::getSymbolIndex() const {
    return symbolIndex;
}

bool BFDInterface::s_bfdInited = false;

BFDInterface::BFDInterface(const std::string &fileName) : ExecutableFile(fileName) {
    m_bfd = NULL;
    m_symbolTable = NULL;
    // Fail loading if the image has no symbols
    m_requireSymbols = true;

    auto ErrorOrMemBuff = llvm::MemoryBuffer::getFile(fileName);
    if (std::error_code EC = ErrorOrMemBuff.getError()) {
        std::cerr << "Unable to open " << fileName << " - " << EC.message()
                  << std::endl;
        exit(-1);
    }

    m_file = std::move(ErrorOrMemBuff.get());
    m_binary = NULL;
}

BFDInterface::BFDInterface(const std::string &fileName, bool requireSymbols) :
        ExecutableFile(fileName) {
    auto ErrorOrMemBuff = llvm::MemoryBuffer::getFile(fileName);
    if (std::error_code EC = ErrorOrMemBuff.getError()) {
        std::cerr << "Unable to open " << fileName << std::endl;
        exit(-1);
    }

    m_bfd = NULL;
    m_symbolTable = NULL;
    m_requireSymbols = requireSymbols;
    m_file = std::move(ErrorOrMemBuff.get());
    m_binary = NULL;
}

BFDInterface::~BFDInterface()
{
    if (m_binary) {
        delete m_binary;
    }

    if (m_bfd) {
        free(m_symbolTable);
        bfd_close(m_bfd);
    }
}

void BFDInterface::initSections(bfd *abfd, asection *sect, void *obj) {
    BFDInterface *bfdptr = (BFDInterface*)obj;
    BFDSection s(sect->vma, sect->size);

    // Deal with relocations
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

bool BFDInterface::initialize() {
    return initialize("");
}

bool BFDInterface::initialize(const std::string &format) {
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

    m_bfd = bfd_fopen(m_fileName.c_str(), bfdFormat, "rw", -1);
    if (!m_bfd) {
        std::cerr << "Could not open bfd file " << m_fileName << " - "
                  << bfd_errmsg(bfd_get_error()) << std::endl;

        return false;
    }

    if (!bfd_check_format(m_bfd, bfd_object)) {
        std::cerr << m_fileName << " has invalid format " << std::endl;
        bfd_close(m_bfd);
        m_bfd = NULL;

        return false;
    }

    long storage_needed = bfd_get_symtab_upper_bound(m_bfd);
    long number_of_symbols;

    if (storage_needed < 0) {
        std::cerr << "Failed to determine needed storage" << std::endl;
        bfd_close(m_bfd);
        m_bfd = NULL;

        return false;
    }

    m_symbolTable = (asymbol**) malloc(storage_needed);
    number_of_symbols = bfd_canonicalize_symtab(m_bfd, m_symbolTable);
    if (number_of_symbols < 0) {
        std::cerr << "Failed to determine number of symbols" << std::endl;
        bfd_close(m_bfd);
        m_bfd = NULL;

        return false;
    }

    m_symbolCount = number_of_symbols;

    if (m_requireSymbols && !(m_bfd->flags & HAS_SYMS)) {
        return false;
    }

    bfd_map_over_sections(m_bfd, initSections, this);

    // Compute image base
    // XXX: Make sure it is correct
    uint64_t vma = (uint64_t) -1;
    for (auto const& sec : m_sections) {
        asection *section = sec.second;
        if (section->vma && (section->vma < vma)) {
            vma = section->vma;
        }
    }
    assert(vma);
    m_imageBase = vma & (uint64_t)~0xFFF;

    if (PeReader::isValid(m_file.get())) {
        m_binary = new PeReader(this);
    } else if (MachoReader::isValid(m_file.get())) {
        m_binary = new MachoReader(this);
    }

    // Extract module name
    size_t pos = m_fileName.find_last_of("\\/");
    if (pos == std::string::npos) {
        m_moduleName = m_fileName;
    } else {
        m_moduleName = m_fileName.substr(pos);
    }

    return true;
}

bool BFDInterface::getInfo(uint64_t addr, std::string &source, uint64_t &line, std::string &function) {
    if (!initialize()) {
        return false;
    }

    BFDSection s(addr, 1);

    if (m_invalidAddresses.find(addr) != m_invalidAddresses.end()) {
        return false;
    }

    Sections::const_iterator it = m_sections.find(s);
    if (it == m_sections.end()) {
        std::cerr << "Could not find section at address 0x"
                  << std::hex << addr << " in file " << m_fileName
                  << std::endl;
        // Cache the value for speed  up
        m_invalidAddresses.insert(addr);
        return false;
    }

    asection *section = (*it).second;

    const char *filename;
    const char *funcname;
    unsigned int sourceline;

    if (bfd_find_nearest_line(m_bfd, section, m_symbolTable, addr - section->vma,
            &filename, &funcname, &sourceline)) {
        source = filename ? filename : "<unknown source>" ;
        line = sourceline;
        function = funcname ? funcname:"<unknown function>";

        if (!filename && !line && !funcname) {
            return false;
        } else {
            return true;
        }
    }

    return false;

}

bool BFDInterface::inited() const {
    return m_bfd != NULL;
}

bool BFDInterface::getModuleName(std::string &name ) const {
    if (!m_bfd) {
        return false;
    }

    name = m_moduleName;
    return true;
}

uint64_t BFDInterface::getImageBase() const {
    if (!m_bfd) {
        return false;
    }

    return m_imageBase;
}

uint64_t BFDInterface::getImageSize() const {
    if (!m_bfd) {
        return false;
    }

    return bfd_get_size(m_bfd);
}

uint64_t BFDInterface::getEntryPoint() const {
    if (!m_bfd) {
        return 0;
    }

    return m_bfd->start_address;
}

asection *BFDInterface::getSection(uint64_t va, unsigned size) const {
    if (!m_bfd) {
        return NULL;
    }

    BFDSection s(va, size);

    Sections::const_iterator it = m_sections.find(s);
    if (it == m_sections.end()) {
        return NULL;
    }

    assert((*it).second->vma <= va);
    return (*it).second;
}

bool BFDInterface::read(uint64_t va, void *dest, unsigned size) const {
    asection *section = getSection(va, 1);
    if (!section) {
        return false;
    }

    bool b = bfd_get_section_contents(m_bfd, section, dest, va - section->vma, size);
    //Check for written changes
    for (unsigned i = 0; i < size; ++i) {
        std::map<uint64_t, uint8_t>::const_iterator it = m_cowBuffer.find(va+i);
        if (it != m_cowBuffer.end()) {
            *(((uint8_t*)dest) + i) = (*it).second;
        }
    }

    return b;
}

bool BFDInterface::write(uint64_t va, const void *source, unsigned size)
{
    asection *section = getSection(va, 1);
    if (!section) {
        return false;
    }

    //Write data to a local buffer instead of the bfd
    for (unsigned i = 0; i < size; ++i) {
        m_cowBuffer[va+i] = *(((uint8_t*)source) + i);
    }

    return true;
    //XXX: This always seems to fail, because bfd_direction is not properly set for
    //some reason.
    //return bfd_set_section_contents(m_bfd, section, source, va - section->vma, size);
}

bool BFDInterface::isCode(uint64_t va) const {
    asection *section = getSection(va, 1);
    if (!section) {
        return false;
    }

    return section->flags & SEC_CODE;
}

bool BFDInterface::isData(uint64_t va) const {
    asection *section = getSection(va, 1);
    if (!section) {
        return false;
    }

    return section->flags & SEC_DATA;
}

int BFDInterface::getSectionFlags(uint64_t va) const {
    asection *section = getSection(va, 1);
    if (!section) {
        return false;
    }

    return section->flags;
}

const BFDInterface::Sections &BFDInterface::getSections() const {
    return m_sections;
}

asymbol **BFDInterface::getSymbols() const {
    return m_symbolTable;
}

long BFDInterface::getSymbolCount() const {
    return m_symbolCount;
}

llvm::MemoryBuffer *BFDInterface::getFile() const {
    return m_file.get();
}

/*
 * The following clang pragmas are required because of a bug in clang. This bug
 * causes clang to wrongly claim that the function returns a stack address
 * when it is in fact returning an address on the heap.
 *
 * See https://llvm.org/bugs/show_bug.cgi?id=21218 for details.
 */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-stack-address"
const Imports &BFDInterface::getImports() const {
    if (!m_binary) {
        return m_imports;
    } else {
        return m_binary->getImports();
    }
}
#pragma clang diagnostic pop

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-stack-address"
const RelocationEntries &BFDInterface::getRelocations() const {
    if (!m_binary) {
        return m_relocations;
    } else {
        return m_binary->getRelocations();
    }
}
#pragma clang diagnostic pop

} // namespace s2etools
