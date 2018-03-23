/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2014, Cisco Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Cisco Systems nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CISCO SYSTEMS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "s2e.h"

#define MIN(x, y) ((x) > (y) ? (y) : (x))

/* file is a path relative to the HostFile's base directory */
static int copy_file(const char *file, int get_example)
{
    const char *guest_file = basename((char*)file);
    if (!guest_file) {
        fprintf(stderr, "Could not allocate memory for file basename\n");
        exit(1);
    }

    int oflags = O_RDONLY;
#ifdef _WIN32
    oflags |= O_BINARY;
#endif

    int fd = open(file, oflags);

    if(fd == -1) {
        fprintf(stderr, "cannot open file %s\n", file);
        exit(1);
    }

    int s2e_fd = s2e_create(guest_file);
    if(s2e_fd == -1) {
        fprintf(stderr, "s2e_create of %s failed\n", guest_file);
        exit(1);
    }

    struct stat st;
    stat(file, &st);

    char *buf = malloc(st.st_size);
    if(!buf) {
        fprintf(stderr, "can not allocate %zu bytes\n", (size_t) st.st_size);
        exit(1);
    }

    int ret = read(fd, buf, st.st_size);
    if(ret != st.st_size) {
        fprintf(stderr, "can not read file\n");
        exit(1);
    }

    if (get_example) {
        // Have to call s2e_get_example for the whole file at once as it doesn't add constraints.
        // Calling s2e_concretize produces silent concretization warnings.
        s2e_get_example(buf, st.st_size);
    }

    off_t off = 0;
    while(off < st.st_size){
        size_t to_send = MIN(64 * 1024, st.st_size - off);
        ret = s2e_write(s2e_fd, buf + off, to_send);
        if(ret != to_send) {
            fprintf(stderr, "s2e_write failed\n");
            exit(1);
        }
        off += ret;
    }

    printf("... file %s of size %zu was transferred successfully\n", file, (size_t) st.st_size);

    free(buf);
    s2e_close(s2e_fd);
    close(fd);

    return 0;
}

static int parse_arguments(int argc, const char **argv, const char **file, int *get_example)
{
    if (argc < 2) {
        return -1;
    }

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            *get_example = 1;
        } else {
            fprintf(stderr, "invalid option: %s\n", argv[i]);
            return -1;
        }
    }

    *file = argv[argc - 1];

    return 0;
}

static int validate_arguments(const char *file)
{
    if (!file) {
        return -1;
    }

    return 0;
}

static void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-e] file_name\n", prog_name);
  // XXX : add possibility to write in subdirectory ?
  // (will have to modify HostFiles for that)
  //  fprintf(stderr, "Options:\n");
  //  fprintf(stderr, "  --target-dir : where to place the downloaded file [default: working directory]\n");
}

int main(int argc, const char** argv)
{
    const char *file = NULL;
    int get_example = 0;

    if(parse_arguments(argc, argv, &file, &get_example) < 0) {
        print_usage(argv[0]);
        exit(1);
    }

    if(validate_arguments(file) < 0) {
        print_usage(argv[0]);
        exit(1);
    }

    printf("Waiting for S2E mode...\n");
    while(s2e_version() == 0) /* nothing */;
    printf("... S2E mode detected\n");

    copy_file(file, get_example);

    return 0;
}

