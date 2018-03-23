///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <vmi/FileProvider.h>

namespace vmi {

FileSystemFileProvider::FileSystemFileProvider(const std::string &file) :
        m_file(file), m_fp(NULL) {
}

FileSystemFileProvider::~FileSystemFileProvider()
{
    if (m_fp) {
        fclose(m_fp);
    }
}

bool FileSystemFileProvider::open(bool writable)
{
    const char *mode;
    if (writable) {
        mode = "r+b";
    } else {
        mode = "rb";
    }

    m_fp = fopen(m_file.c_str(), mode);
    if (!m_fp) {
        return false;
    }

    return true;
}

ssize_t FileSystemFileProvider::read(void *buffer, size_t nbyte, off64_t offset)
{
    if (nbyte == 0) {
        return nbyte;
    }

    if (this->seek(offset) < 0) {
        return -1;
    }

    if (::fread(buffer, nbyte, 1, m_fp) != 1) {
        return -1;
    }

    return nbyte;
}

ssize_t FileSystemFileProvider::write(const void *buffer, size_t nbyte, off64_t offset)
{
    if (nbyte == 0) {
        return nbyte;
    }

    if (this->seek(offset) < 0) {
        return -1;
    }

    if (::fwrite(buffer, nbyte, 1, m_fp) != 1) {
        return -1;
    }

    return nbyte;
}

ssize_t FileSystemFileProvider::writep(const void *buffer, size_t nbyte)
{
    assert(m_fp);

    if (nbyte == 0) {
        return nbyte;
    }

    if (::fwrite(buffer, nbyte, 1, m_fp) != 1) {
        return -1;
    }

    return nbyte;
}

off64_t FileSystemFileProvider::seek(off64_t offset)
{
    assert(m_fp);

    if (::fseek(m_fp, offset, SEEK_SET) < 0) {
        return -1;
    }

    return offset;
}

off64_t FileSystemFileProvider::tell()
{
    assert(m_fp);
    return ::ftell(m_fp);
}

int FileSystemFileProvider::stat(struct stat *buf)
{
    assert(m_fp);
    return ::fstat(fileno(m_fp), buf);
}

const char *FileSystemFileProvider::getName() const
{
    return m_file.c_str();
}

/************************************************************/

GuestMemoryFileProvider::GuestMemoryFileProvider(void *opaque,
                                                 ReadMemoryCb readCb,
                                                 WriteMemoryCb writeCb,
                                                 const std::string &name)
{
    m_opaque = opaque;
    m_read = readCb;
    m_write = writeCb;
    m_name = name;
}


GuestMemoryFileProvider::~GuestMemoryFileProvider()
{

}

bool GuestMemoryFileProvider::open(bool writable)
{
    if (writable) {
        if (!m_write) {
            return false;
        }
    } else {
        m_write = NULL;
    }
    return true;
}

ssize_t GuestMemoryFileProvider::read(void *buffer, size_t nbyte, off64_t offset)
{
    if (m_read(m_opaque, offset, buffer, nbyte)) {
        return nbyte;
    }
    return -1;
}

ssize_t GuestMemoryFileProvider::write(const void *buffer, size_t nbyte, off64_t offset)
{
    if (m_write && m_write(m_opaque, offset, buffer, nbyte)) {
        return nbyte;
    }
    return -1;
}

int GuestMemoryFileProvider::stat(struct stat *buf)
{
    memset(buf, 0, sizeof(*buf));
    //XXX: fix me
    buf->st_size = -1;
    return 0;
}

const char *GuestMemoryFileProvider::getName() const
{
    return m_name.c_str();
}

}
