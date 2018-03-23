/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2013, Dependable Systems Laboratory, EPFL
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
 * Written by Bin Zhang <bin.zhang@epfl.ch>
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#ifndef FILELOCK_H_
#define FILELOCK_H_

#include <sys/file.h>
#include <unistd.h>

void lock_init(struct flock *lock, short type, short whence, off_t start, off_t len);
pid_t lock_test(int fd, short type, short whence, off_t start, off_t len);

int readw_lock(int fd);
int writew_lock(int fd);

int unlock(int fd);


void lock_init(struct flock *lock, short type, short whence, off_t start, off_t len)
{
    if (lock == NULL)
        return;

    lock->l_type = type;
    lock->l_whence = whence;
    lock->l_start = start;
    lock->l_len = len;
}

int readw_lock(int fd)
{
    struct flock lock;
    lock_init(&lock, F_RDLCK, SEEK_SET, 0, 0);

    if (fcntl(fd, F_SETLKW, &lock) != 0)
    {
        return -1;
    }

    return 0;
}

int writew_lock(int fd)
{
    struct flock lock;
    lock_init(&lock, F_WRLCK, SEEK_SET, 0, 0);

    if (fcntl(fd, F_SETLKW, &lock) != 0)
    {
        return -1;
    }

    return 0;
}

int unlock(int fd)
{
    struct flock lock;
    lock_init(&lock, F_UNLCK, SEEK_SET, 0, 0);

    if (fcntl(fd, F_SETLKW, &lock) != 0)
    {
        return -1;
    }

    return 0;
}

pid_t lock_test(int fd, short type, short whence, off_t start, off_t len)
{
    struct flock lock;
    lock_init(&lock, type, whence, start, len);

    if (fcntl(fd, F_GETLK, &lock) == -1)
    {
        return -1;
    }

    if(lock.l_type == F_UNLCK)
        return 0;
    return lock.l_pid;
}



#endif /* FILELOCK_H_ */
