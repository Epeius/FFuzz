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

#include <iostream>
#include <cassert>
#include "LogParser.h"

#ifdef _WIN32
#include <windows.h>
#else

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>



#endif

//#define DEBUG_LP

using namespace s2e::plugins;

namespace s2etools
{

void LogEvents::processItem(unsigned currentItem,
                         const s2e::plugins::ExecutionTraceItemHeader &hdr,
                         void *data)
{
    assert(hdr.type < TRACE_MAX);

#ifdef DEBUG_LP
    std::cout << "Item " << currentItem << " sid=" << (int)hdr.stateId <<
            " type=" << (int) hdr.type << std::endl;
#endif

    onEachItem.emit(currentItem, hdr, (void*)data);
}

LogEvents::LogEvents()
{

}

LogEvents::~LogEvents()
{

}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

LogParser::LogParser():LogEvents()
{
    m_cachedProcessor = NULL;
    m_cachedState = NULL;
}

LogParser::~LogParser()
{

    LogFiles::iterator it;
    for(it=m_files.begin(); it != m_files.end(); ++it) {
        LogFile &file = *it;
        #ifdef _WIN32
        UnmapViewOfFile(file.m_File);
        CloseHandle(file.m_hMapping);
        CloseHandle(file.m_hFile);
        #else
        if (file.m_File) {
            munmap(file.m_File, file.m_size);
        }
        #endif
    }
}


bool LogParser::parse(const std::vector<std::string> fileNames)
{
    std::vector<std::string>::const_iterator it;
    for (it = fileNames.begin(); it != fileNames.end(); ++it) {
        if (!parse(*it)) {
            std::cerr << *it << " is incomplete" << std::endl;
        }
    }
    return true;
}


bool LogParser::parse(const std::string &fileName)
{
    LogFile element;

#ifdef _WIN32
    element.m_hFile = CreateFile(fileName.c_str(), GENERIC_READ,
                              FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              NULL);
    if (element.m_hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER FileSize;
    if (!GetFileSizeEx(element.m_hFile, &FileSize)) {
        CloseHandle(element.m_hFile);
        return false;
    }

    element.m_hMapping = CreateFileMapping(element.m_hFile, NULL, PAGE_READONLY, FileSize.HighPart, FileSize.LowPart, NULL);
    if (element.m_hMapping == NULL) {
        CloseHandle(element.m_hFile);
        return false;
    }

    element.m_File = MapViewOfFile(element.m_hMapping, PAGE_READONLY, FileSize.HighPart, FileSize.LowPart, 0);
    if (!element.m_File) {
        CloseHandle(element.m_hMapping);
        CloseHandle(element.m_hFile);
        return false;
    }

    element.m_size = FileSize.QuadPart;

#else
    int file = open(fileName.c_str(), O_RDONLY);
    if (file<0) {
        std::cerr << "LogParser: Could not open " << fileName << std::endl;
        return false;
    }

    off_t fileSize = lseek(file, 0, SEEK_END);
    if (fileSize == (off_t) -1) {
        std::cerr << "Could not get log file size" << std::endl;
        return false;
    }

    element.m_File = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, file, 0);
    if (!element.m_File) {
        std::cerr << "Could not map the log file in memory" << std::endl;
        close(file);
        return false;
    }

    element.m_size = fileSize;

#endif


    uint64_t currentOffset = 0;
    unsigned currentItem = m_ItemAddresses.size();

    uint8_t *buffer = (uint8_t*)element.m_File;

    while(currentOffset < element.m_size) {

        s2e::plugins::ExecutionTraceItemHeader *hdr =
                (s2e::plugins::ExecutionTraceItemHeader *)(buffer);

        if (currentOffset + sizeof(s2e::plugins::ExecutionTraceItemHeader) > element.m_size) {
            std::cerr << "LogParser: Could not read header " << std::endl;
            return false;
        }

        buffer += sizeof(*hdr);

        if (hdr->size > 0) {
            if (currentOffset + hdr->size > element.m_size) {
                std::cerr << "LogParser: Could not read payload " << std::endl;
                return false;
            }
        }

#ifdef DEBUG_PB
        std::cout << fileName <<  " item=" << currentItem << " buffer="   << (void*)buffer <<
                     " ts=" << hdr->timeStamp <<  " offset=" << currentOffset << std::endl;
#endif
        processItem(currentItem, *hdr, buffer);
        buffer+=hdr->size;

        m_ItemAddresses.push_back(currentOffset + (uint8_t*)element.m_File);

        currentOffset += sizeof(s2e::plugins::ExecutionTraceItemHeader)  + hdr->size;

        ++currentItem;
    }

    m_files.push_back(element);
    //fclose(file);
    return true;
}

bool LogParser::getItem(unsigned index, s2e::plugins::ExecutionTraceItemHeader &hdr, void **data)
{
    if (index >= m_ItemAddresses.size() ) {
        assert(false);
        return false;
    }

    uint8_t *buffer = m_ItemAddresses[index];
    hdr = *(s2e::plugins::ExecutionTraceItemHeader*)buffer;

    *data = NULL;
    if (hdr.size > 0) {
        *data = buffer + sizeof(s2e::plugins::ExecutionTraceItemHeader);
    }

    return true;
}

ItemProcessorState* LogParser::getState(void *processor, ItemProcessorStateFactory f)
{
    if (processor == m_cachedProcessor) {
        return m_cachedState;
    }

    ItemProcessorState *ret;
    ItemProcessors::const_iterator it = m_ItemProcessors.find(processor);
    if (it == m_ItemProcessors.end()) {
        ret = f();
        m_ItemProcessors[processor] = ret;
    } else {
        ret = (*it).second;
    }

    m_cachedProcessor = processor;
    m_cachedState = ret;
    return ret;
}

ItemProcessorState* LogParser::getState(void *processor, uint32_t pathId)
{
    assert(pathId == 0);
    ItemProcessors::const_iterator it = m_ItemProcessors.find(processor);
    if (it == m_ItemProcessors.end()) {
        return NULL;
    } else {
        return (*it).second;
    }
}

//A flat trace has only one path
void LogParser::getPaths(PathSet &s)
{
    s.clear();
    s.insert(0);
}


}
