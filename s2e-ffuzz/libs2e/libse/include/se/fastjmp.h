/// Copyright (c) 2010, Dependable Systems Laboratory, EPFL
/// Copyright (c) 2016, Cyberhaven, Inc
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are met:
///
///    * Redistributions of source code must retain the above copyright
///      notice, this list of conditions and the following disclaimer.
///
///    * Redistributions in binary form must reproduce the above copyright
///      notice, this list of conditions and the following disclaimer in the
///      documentation and/or other materials provided with the distribution.
///
///    * Neither the names of the copyright holders, nor the
///      names of its contributors may be used to endorse or promote products
///      derived from this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
/// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
/// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
/// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
/// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
/// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
/// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef FASTLJLJ_H

#define FASTLJLJ_H

#if defined(CONFIG_SYMBEX)
#include <setjmp.h>
#include <inttypes.h>

struct _fast_jmpbuf_t
{
    uint64_t gpregs[16];
    uint64_t rip;
};

typedef struct _fast_jmpbuf_t fast_jmp_buf[1];

#ifdef __cplusplus
extern "C" {
#endif

int fast_setjmp_win32(fast_jmp_buf buf);
int fast_longjmp_win32(fast_jmp_buf buf, int value) __attribute__((noreturn));

int fast_setjmp_posix(fast_jmp_buf buf);
int fast_longjmp_posix(fast_jmp_buf buf, int value) __attribute__((noreturn));


#ifdef __cplusplus
}
#endif

#ifdef _WIN32
#define fast_setjmp fast_setjmp_win32
#define fast_longjmp fast_longjmp_win32
#else
#define fast_setjmp fast_setjmp_posix
#define fast_longjmp fast_longjmp_posix
#endif

#else

#include <setjmp.h>

#define fast_setjmp setjmp
#define fast_longjmp longjmp
#define fast_jmp_buf jmp_buf

#endif

#endif
