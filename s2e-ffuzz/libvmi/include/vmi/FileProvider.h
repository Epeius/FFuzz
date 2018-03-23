///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#ifndef VMI_FILEPROVIDER_H

#define VMI_FILEPROVIDER_H

#include <vector>
#include <string>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

namespace vmi
{

class FileProvider {
public:
    virtual ~FileProvider() {}

    //XXX: use bool as return values, more intuitive.
    virtual bool open(bool writable) = 0;
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset) = 0;
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset) = 0;
    virtual ssize_t writep(const void *buffer, size_t nbyte) { return -1; }
    virtual off64_t seek(off64_t offset) { return -1; }
    virtual off64_t tell()  { return -1; }
    virtual int stat(struct stat *buf) = 0;
    virtual const char *getName() const = 0;

    bool readb(void *buffer, size_t nbyte, off64_t offset) {
        ssize_t ret = read(buffer, nbyte, offset);
        if (ret < 0) {
            return false;
        }

        return (size_t) ret == nbyte;
    }

    bool writeb(const void *buffer, size_t nbyte, off64_t offset) {
        ssize_t ret = write(buffer, nbyte, offset);
        if (ret < 0) {
            return false;
        }

        return (size_t) ret == nbyte;
    }

    bool writeb(const void *buffer, size_t nbyte) {
        ssize_t ret = writep(buffer, nbyte);
        if (ret < 0) {
            return false;
        }

        return (size_t) ret == nbyte;
    }

    /** Read a generic string from memory */
    template <typename T>
    bool readGenericString(uint64_t address, std::string &s, unsigned maxLen) {
        s = "";
        bool ret = false;
        T c;

        do {
            c = 0;
            ret = readb(&c, sizeof(c), address);
            maxLen--;
            address += sizeof(T);

            if (c) {
                s = s + (char)c;
            }

        } while(c && (maxLen > 0));

        return ret;
    }

    /** Read an ASCIIZ string */
    bool readString(uint64_t address, std::string &s, unsigned maxLen=256) {
        return readGenericString<uint8_t>(address, s, maxLen);
    }

    /** Read a unicode string */
    bool readUnicodeString(uint64_t address, std::string &s, unsigned maxLen=256) {
        return readGenericString<uint16_t>(address, s, maxLen);
    }
};

class FileSystemFileProvider : public FileProvider {
private:
    std::string m_file;
    // Use buffered files to avoid too many syscalls (most reads are a few bytes large).
    FILE *m_fp;

public:

    FileSystemFileProvider(const std::string &file);
    virtual ~FileSystemFileProvider();

    virtual bool open(bool writable);
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset);
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset);
    virtual ssize_t writep(const void *buffer, size_t nbyte);
    virtual off64_t seek(off64_t offset);
    virtual off64_t tell();
    virtual int stat(struct stat *buf);
    virtual const char *getName() const;
};


class GuestMemoryFileProvider : public FileProvider {
public:
    typedef bool (*ReadMemoryCb)(void *opaque, uint64_t address, void *buffer, unsigned size);
    typedef bool (*WriteMemoryCb)(void *opaque, uint64_t address, const void *buffer, unsigned size);

private:
    ReadMemoryCb m_read;
    WriteMemoryCb m_write;
    void *m_opaque;
    std::string m_name;

public:

    GuestMemoryFileProvider(void *opaque, ReadMemoryCb readCb,
                            WriteMemoryCb writeCb, const std::string &name);
    virtual ~GuestMemoryFileProvider();

    virtual bool open(bool writable);
    virtual ssize_t read(void *buffer, size_t nbyte, off64_t offset);
    virtual ssize_t write(const void *buffer, size_t nbyte, off64_t offset);
    virtual int stat(struct stat *buf);
    virtual const char *getName() const;
};

}

#endif
