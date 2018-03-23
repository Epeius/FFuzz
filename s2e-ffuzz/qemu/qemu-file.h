/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef QEMU_FILE_H
#define QEMU_FILE_H 1

/* This function writes a chunk of data to a file at the given position.
 * The pos argument can be ignored if the file is only being used for
 * streaming.  The handler should try to write all of the data it can.
 */
typedef int (QEMUFilePutBufferFunc)(void *opaque, const uint8_t *buf,
                                    int64_t pos, int size);

/* Read a chunk of data from a file at the given position.  The pos argument
 * can be ignored if the file is only be used for streaming.  The number of
 * bytes actually read should be returned.
 */
typedef int (QEMUFileGetBufferFunc)(void *opaque, uint8_t *buf,
                                    int64_t pos, int size);

/* Close a file
 *
 * Return negative error number on error, 0 or positive value on success.
 *
 * The meaning of return value on success depends on the specific back-end being
 * used.
 */
typedef int (QEMUFileCloseFunc)(void *opaque);

/* Called to determine if the file has exceeded its bandwidth allocation.  The
 * bandwidth capping is a soft limit, not a hard limit.
 */
typedef int (QEMUFileRateLimit)(void *opaque);

/* Called to change the current bandwidth allocation. This function must return
 * the new actual bandwidth. It should be new_rate if everything goes ok, and
 * the old rate otherwise
 */
typedef int64_t (QEMUFileSetRateLimit)(void *opaque, int64_t new_rate);
typedef int64_t (QEMUFileGetRateLimit)(void *opaque);

QEMUFile *qemu_fopen_ops(void *opaque, QEMUFilePutBufferFunc *put_buffer,
                         QEMUFileGetBufferFunc *get_buffer,
                         QEMUFileCloseFunc *close,
                         QEMUFileRateLimit *rate_limit,
                         QEMUFileSetRateLimit *set_rate_limit,
                         QEMUFileGetRateLimit *get_rate_limit);
QEMUFile *qemu_fopen(const char *filename, const char *mode);
QEMUFile *qemu_fdopen(int fd, const char *mode);
QEMUFile *qemu_fopen_socket(int fd);
QEMUFile *qemu_popen(FILE *popen_file, const char *mode);
QEMUFile *qemu_popen_cmd(const char *command, const char *mode);
int qemu_stdio_fd(QEMUFile *f);
void qemu_fflush(QEMUFile *f);
int qemu_fclose(QEMUFile *f);
void qemu_put_buffer(QEMUFile *f, const uint8_t *buf, int size);
void qemu_put_byte(QEMUFile *f, int v);

typedef int (*memfile_get_buffer_t)(uint8_t *buf, int64_t pos, int size);
typedef int (*memfile_put_buffer_t)(const uint8_t *buf, int64_t pos, int size);
QEMUFile *qemu_memfile_open(memfile_get_buffer_t get, memfile_put_buffer_t put);

/* Called by the load/savevm functions to restore/save the state of the vm */
void *s2e_qemu_get_first_se(void);
void *s2e_qemu_get_next_se(void *se);
const char *s2e_qemu_get_se_idstr(void *se);
void s2e_qemu_save_state(QEMUFile *f, void *se);
void s2e_qemu_load_state(QEMUFile *f, void *se);
void qemu_make_readable(QEMUFile *f);

void qemu_initialize_savevm_timer(void);

static inline void qemu_put_ubyte(QEMUFile *f, unsigned int v)
{
    qemu_put_byte(f, (int)v);
}

#define qemu_put_sbyte qemu_put_byte

void qemu_put_be16(QEMUFile *f, unsigned int v);
void qemu_put_be32(QEMUFile *f, unsigned int v);
void qemu_put_be64(QEMUFile *f, uint64_t v);
int qemu_get_buffer(QEMUFile *f, uint8_t *buf, int size);
int qemu_get_byte(QEMUFile *f);

static inline unsigned int qemu_get_ubyte(QEMUFile *f)
{
    return (unsigned int)qemu_get_byte(f);
}

#define qemu_get_sbyte qemu_get_byte

unsigned int qemu_get_be16(QEMUFile *f);
unsigned int qemu_get_be32(QEMUFile *f);
uint64_t qemu_get_be64(QEMUFile *f);

int qemu_file_rate_limit(QEMUFile *f);
int64_t qemu_file_set_rate_limit(QEMUFile *f, int64_t new_rate);
int64_t qemu_file_get_rate_limit(QEMUFile *f);
int qemu_file_get_error(QEMUFile *f);
void qemu_file_set_error(QEMUFile *f, int error);

/* Try to send any outstanding data.  This function is useful when output is
 * halted due to rate limiting or EAGAIN errors occur as it can be used to
 * resume output. */
void qemu_file_put_notify(QEMUFile *f);

static inline void qemu_put_be64s(QEMUFile *f, const uint64_t *pv)
{
    qemu_put_be64(f, *pv);
}

static inline void qemu_put_be32s(QEMUFile *f, const uint32_t *pv)
{
    qemu_put_be32(f, *pv);
}

static inline void qemu_put_be16s(QEMUFile *f, const uint16_t *pv)
{
    qemu_put_be16(f, *pv);
}

static inline void qemu_put_8s(QEMUFile *f, const uint8_t *pv)
{
    qemu_put_byte(f, *pv);
}

static inline void qemu_get_be64s(QEMUFile *f, uint64_t *pv)
{
    *pv = qemu_get_be64(f);
}

static inline void qemu_get_be32s(QEMUFile *f, uint32_t *pv)
{
    *pv = qemu_get_be32(f);
}

static inline void qemu_get_be16s(QEMUFile *f, uint16_t *pv)
{
    *pv = qemu_get_be16(f);
}

static inline void qemu_get_8s(QEMUFile *f, uint8_t *pv)
{
    *pv = qemu_get_byte(f);
}

// Signed versions for type safety
static inline void qemu_put_sbuffer(QEMUFile *f, const int8_t *buf, int size)
{
    qemu_put_buffer(f, (const uint8_t *)buf, size);
}

static inline void qemu_put_sbe16(QEMUFile *f, int v)
{
    qemu_put_be16(f, (unsigned int)v);
}

static inline void qemu_put_sbe32(QEMUFile *f, int v)
{
    qemu_put_be32(f, (unsigned int)v);
}

static inline void qemu_put_sbe64(QEMUFile *f, int64_t v)
{
    qemu_put_be64(f, (uint64_t)v);
}

static inline size_t qemu_get_sbuffer(QEMUFile *f, int8_t *buf, int size)
{
    return qemu_get_buffer(f, (uint8_t *)buf, size);
}

static inline int qemu_get_sbe16(QEMUFile *f)
{
    return (int)qemu_get_be16(f);
}

static inline int qemu_get_sbe32(QEMUFile *f)
{
    return (int)qemu_get_be32(f);
}

static inline int64_t qemu_get_sbe64(QEMUFile *f)
{
    return (int64_t)qemu_get_be64(f);
}

static inline void qemu_put_s8s(QEMUFile *f, const int8_t *pv)
{
    qemu_put_8s(f, (const uint8_t *)pv);
}

static inline void qemu_put_sbe16s(QEMUFile *f, const int16_t *pv)
{
    qemu_put_be16s(f, (const uint16_t *)pv);
}

static inline void qemu_put_sbe32s(QEMUFile *f, const int32_t *pv)
{
    qemu_put_be32s(f, (const uint32_t *)pv);
}

static inline void qemu_put_sbe64s(QEMUFile *f, const int64_t *pv)
{
    qemu_put_be64s(f, (const uint64_t *)pv);
}

static inline void qemu_get_s8s(QEMUFile *f, int8_t *pv)
{
    qemu_get_8s(f, (uint8_t *)pv);
}

static inline void qemu_get_sbe16s(QEMUFile *f, int16_t *pv)
{
    qemu_get_be16s(f, (uint16_t *)pv);
}

static inline void qemu_get_sbe32s(QEMUFile *f, int32_t *pv)
{
    qemu_get_be32s(f, (uint32_t *)pv);
}

static inline void qemu_get_sbe64s(QEMUFile *f, int64_t *pv)
{
    qemu_get_be64s(f, (uint64_t *)pv);
}

int64_t qemu_ftell(QEMUFile *f);
int64_t qemu_fseek(QEMUFile *f, int64_t pos, int whence);

#endif
