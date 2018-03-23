///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

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

#include <cassert>

#include "S2E.h"
#include "config-host.h"
#include "Synchronization.h"

#ifndef CONFIG_WIN32
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#endif

#ifdef CONFIG_DARWIN
#include <mach/semaphore.h>
#else
#ifndef _WIN32
#include <semaphore.h>
#else

#endif
#include <errno.h>
#endif


namespace s2e {

#if defined(CONFIG_WIN32)

#error Synchronized objects are not implemented on Windows!

S2ESynchronizedObjectInternal::S2ESynchronizedObjectInternal(unsigned size) {
    m_size = size;
    m_headerSize = 0;

    m_sharedBuffer = new uint8_t[size];
}

S2ESynchronizedObjectInternal::~S2ESynchronizedObjectInternal()
{
    delete [] m_sharedBuffer;
}

void *S2ESynchronizedObjectInternal::acquire()
{
    return m_sharedBuffer;
}

void *S2ESynchronizedObjectInternal::tryAquire()
{
    return m_sharedBuffer;
}

void S2ESynchronizedObjectInternal::release()
{

}

#else

struct SyncHeader{
    unsigned lock;
    unsigned inited;
};

#define SYNCHEADER_FREE     1
#define SYNCHEADER_LOCKED   0

/// \brief Create synchronized object
///
/// \param size shared memory size
/// \param name shared memory name
///
S2ESynchronizedObjectInternal::S2ESynchronizedObjectInternal(unsigned size, const char *name)
{
    m_fd = -1;
    m_size = size;
    m_headerSize = sizeof(SyncHeader);

    unsigned totalSize = m_headerSize + size;

    if (name) {
        m_fd = shm_open(name, O_CREAT | O_RDWR, 0600);
        if (m_fd < 0) {
            fprintf(stderr, "Could not open shared memory %s (%d, %s)", name, errno, strerror(errno));
            exit(-1);
        }
    }

    int flags = MAP_SHARED;
    if (m_fd == -1) {
        flags |= MAP_ANON;
    } else {
        if (ftruncate(m_fd, totalSize) < 0) {
            fprintf(stderr, "Could not resize shared memory (%d, %s)", errno, strerror(errno));
            exit(-1);
        }
    }

    m_sharedBuffer = (uint8_t*)mmap(NULL, totalSize, PROT_READ | PROT_WRITE, flags, m_fd, 0);
    if (m_sharedBuffer == MAP_FAILED) {
        fprintf(stderr, "Could not allocate shared memory (%d, %s)", errno, strerror(errno));
        exit(-1);
    }

    SyncHeader *hdr = static_cast<SyncHeader*>((void*)m_sharedBuffer);

    if (!hdr->inited) {
        hdr->lock = SYNCHEADER_FREE;
        hdr->inited = 1;
    }
}

S2ESynchronizedObjectInternal::~S2ESynchronizedObjectInternal()
{
    unsigned totalSize = m_headerSize + m_size;
    munmap(m_sharedBuffer, totalSize);
}

/// \brief Try to acquire synchronization lock
///
/// \returns pointer to shared memory if lock was acquired, otherwise NULL
///
void *S2ESynchronizedObjectInternal::tryAcquire()
{
    SyncHeader *hdr = (SyncHeader*)m_sharedBuffer;

    unsigned expected = SYNCHEADER_FREE; // this variable will contain actual value after call
    if (!__atomic_compare_exchange_n(&hdr->lock, &expected, SYNCHEADER_LOCKED, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        return NULL;
    }

    return ((uint8_t*)m_sharedBuffer + m_headerSize);
}

/// \brief Acquire synchronization lock
///
/// Call \ref tryAquire until it succeeds
///
/// \returns pointer to shared memory
///
void *S2ESynchronizedObjectInternal::acquire()
{
    while (true) {
        void *ret = tryAcquire();
        if (ret != NULL) {
            return ret;
        }
    }
}

/// \brief Release previously acquired lock
void S2ESynchronizedObjectInternal::release()
{
    SyncHeader *hdr = (SyncHeader*)m_sharedBuffer;

    assert(__atomic_load_n(&hdr->lock, __ATOMIC_SEQ_CST) == SYNCHEADER_LOCKED && "Lock was not acquired");
    __atomic_store_n(&hdr->lock, SYNCHEADER_FREE, __ATOMIC_SEQ_CST);
}

#endif

}
