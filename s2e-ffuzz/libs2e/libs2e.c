///
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///


#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include <cpu/kvm.h>
#include "s2e-kvm-interface.h"

static open_t s_original_open;


int g_trace = 0;
int g_kvm_fd = -1;
int g_kvm_vm_fd = -1;
int g_kvm_vcpu = -1;

int open64(const char *pathname, int flags, ...)
{
    va_list list;
    va_start(list, flags);
    mode_t mode = va_arg(list, mode_t);
    va_end(list);

    if (!strcmp(pathname, "/dev/kvm")) {
        printf("Opening %s\n", pathname);
        int fd = s_original_open("/dev/null", flags, mode);
        if (fd < 0) {
            printf("Could not open fake kvm /dev/null\n");
            exit(-1);
        }

        g_kvm_fd = fd;
        return fd;
    } else {
        return s_original_open(pathname, flags, mode);
    }
}

static close_t s_original_close;
int close64(int fd)
{
    if (fd == g_kvm_fd) {
        printf("close %d\n", fd);
        close(fd);
        g_kvm_fd = -1;
        return 0;
    } else {
        return s_original_close(fd);
    }
}

static write_t s_original_write;
ssize_t write(int fd, const void *buf, size_t count)
{
    if (fd == g_kvm_fd || fd == g_kvm_vm_fd) {
        printf("write %d count=%ld\n", fd, count);
        exit(-1);
    } else {
        return s_original_write(fd, buf, count);
    }
}

static sigaction_t s_original_sigaction;

static struct sigaction s_oldsigs[256];

static void handle_sigaction(int num, siginfo_t *info, void *data)
{
    if (!g_trace) {
        s2e_kvm_signal_handler(num);
    } else {
        printf("Signal %d\n", num);
    }
    s_oldsigs[num].sa_sigaction(num, info, data);
}

int sigaction(int signum, const struct sigaction *act,
                    struct sigaction *oldact)
{

    assert(signum < 256);
    //printf("Registering signal %d (old=%p)\n", signum, oldact);
    struct sigaction myact;

    if (act) {
        s_oldsigs[signum] = *act;
        //printf("handler=%p action=%p flags=%#x\n", act->sa_handler, act->sa_sigaction, act->sa_flags);
        if (act->sa_handler != SIG_IGN && act->sa_handler != SIG_DFL) {
            myact = *act;
            myact.sa_sigaction = handle_sigaction;
            act = &myact;
        }
    }

    return s_original_sigaction(signum, act, oldact);
}


static int handle_kvm_ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;

    switch((uint32_t) request) {
        case KVM_GET_API_VERSION:
            return s2e_kvm_get_api_version();

        case KVM_CHECK_EXTENSION:
            ret = s2e_kvm_check_extension(fd, arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_CREATE_VM: {
            int tmpfd = s2e_kvm_create_vm(fd);
            if (tmpfd < 0) {
                printf("Could not create vm fd (errno=%d %s)\n", errno, strerror(errno));
                exit(-1);
            }
            g_kvm_vm_fd = tmpfd;
            ret = tmpfd;
        }
        break;

        case KVM_GET_VCPU_MMAP_SIZE: {
            ret = s2e_kvm_get_vcpu_mmap_size();
        } break;

        case KVM_GET_MSR_INDEX_LIST: {
            ret = s2e_kvm_get_msr_index_list(fd, (struct kvm_msr_list*) arg1);
        } break;

        case KVM_GET_SUPPORTED_CPUID: {
            ret = s2e_kvm_get_supported_cpuid(fd, (struct kvm_cpuid2*) arg1);
        } break;

        default: {
            //return s_original_ioctl(fd, request, arg1);
            exit(-1);
        }
    }

    return ret;
}

static int handle_kvm_vm_ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_SET_TSS_ADDR: {
            ret = s2e_kvm_vm_set_tss_addr(fd, arg1);
        }
        break;

        case KVM_CREATE_VCPU: {
            ret = s2e_kvm_vm_create_vcpu(fd);
            printf("Created vcpu %d\n", ret);
            g_kvm_vcpu = ret;
        } break;

        case KVM_SET_USER_MEMORY_REGION: {
            ret = s2e_kvm_vm_set_user_memory_region(fd, (struct kvm_userspace_memory_region*) arg1);
        } break;

        case KVM_SET_CLOCK: {
            ret = s2e_kvm_vm_set_clock(fd, (struct kvm_clock_data*) arg1);
        } break;

        case KVM_ENABLE_CAP: {
            ret = s2e_kvm_vm_enable_cap(fd, (struct kvm_enable_cap*) arg1);
        } break;

        case KVM_IOEVENTFD: {
            ret = s2e_kvm_vm_ioeventfd(fd, (struct kvm_ioeventfd*) arg1);
        } break;

        case KVM_SET_IDENTITY_MAP_ADDR: {
            ret = s2e_kvm_vm_set_identity_map_addr(fd, arg1);
        } break;

        case KVM_GET_DIRTY_LOG: {
            ret = s2e_kvm_vm_get_dirty_log(fd, (struct kvm_dirty_log*) arg1);
        } break;

        case KVM_MEM_RW: {
            ret = s2e_kvm_vm_mem_rw(fd, (struct kvm_mem_rw*) arg1);
        } break;

        default: {
            exit(-1);
        }
    }

    return ret;
}

static int handle_kvm_vcpu_ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;
    switch ((uint32_t) request) {
        case KVM_GET_CLOCK: {
            ret = s2e_kvm_vcpu_get_clock(fd, (struct kvm_clock_data*) arg1);
        } break;

        case KVM_SET_CPUID2: {
            ret = s2e_kvm_vcpu_set_cpuid2(fd, (struct kvm_cpuid2 *) arg1);
        } break;

        case KVM_SET_SIGNAL_MASK: {
            ret = s2e_kvm_vcpu_set_signal_mask(fd, (struct kvm_signal_mask*) arg1);
        } break;

        /***********************************************/
        case KVM_SET_REGS: {
            ret = s2e_kvm_vcpu_set_regs(fd, (struct kvm_regs*) arg1);
        } break;

        case KVM_SET_FPU: {
            ret = s2e_kvm_vcpu_set_fpu(fd, (struct kvm_fpu*) arg1);
        } break;

        case KVM_SET_SREGS: {
            ret = s2e_kvm_vcpu_set_sregs(fd, (struct kvm_sregs*) arg1);
        } break;

        case KVM_SET_MSRS: {
            ret = s2e_kvm_vcpu_set_msrs(fd, (struct kvm_msrs*) arg1);
        } break;

        case KVM_SET_MP_STATE: {
            ret = s2e_kvm_vcpu_set_mp_state(fd, (struct kvm_mp_state*) arg1);
        } break;
        /***********************************************/
        case KVM_GET_REGS: {
            ret = s2e_kvm_vcpu_get_regs(fd, (struct kvm_regs*) arg1);
        } break;

        case KVM_GET_FPU: {
            ret = s2e_kvm_vcpu_get_fpu(fd, (struct kvm_fpu*) arg1);
        } break;

        case KVM_GET_SREGS: {
            ret = s2e_kvm_vcpu_get_sregs(fd, (struct kvm_sregs*) arg1);
        } break;

        case KVM_GET_MSRS: {
            ret = s2e_kvm_vcpu_get_msrs(fd, (struct kvm_msrs*) arg1);
        } break;

        case KVM_GET_MP_STATE: {
            ret = s2e_kvm_vcpu_get_mp_state(fd, (struct kvm_mp_state*) arg1);
        } break;

        /***********************************************/
        case KVM_RUN: {
            return s2e_kvm_vcpu_run(fd);
        } break;

        case KVM_INTERRUPT: {
            ret = s2e_kvm_vcpu_interrupt(fd, (struct kvm_interrupt*) arg1);
        } break;

        default:  {
            printf("ioctl vcpu %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            exit(-1);
        }
    }

    return ret;
}

ioctl_t g_original_ioctl;
int ioctl(int fd, int request, uint64_t arg1)
{
    int ret = -1;

    if (g_trace) {
        if (fd == g_kvm_fd) {
            //printf("ioctl %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_ioctl_trace(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            //printf("ioctl vm %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_vm_ioctl_trace(fd, request, arg1);
        } else if (fd == g_kvm_vcpu) {
            ret = handle_kvm_vcpu_ioctl_trace(fd, request, arg1);
        } else {
            //printf("ioctl on %d\n", fd);
            ret = g_original_ioctl(fd, request, arg1);
        }
    } else {
        if (fd == g_kvm_fd) {
            //printf("ioctl %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            //printf("ioctl vm %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd, request, arg1, ret);
            ret = handle_kvm_vm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vcpu) {
            ret = handle_kvm_vcpu_ioctl(fd, request, arg1);
        }  else {
            //printf("ioctl on %d\n", fd);
            ret = g_original_ioctl(fd, request, arg1);
        }
    }

    return ret;
}

// ****************************
// Overriding __llibc_start_main
// ****************************

// The type of __libc_start_main
typedef int (*T_libc_start_main)(
        int *(main) (int, char**, char**),
        int argc,
        char ** ubp_av,
        void (*init) (void),
        void (*fini) (void),
        void (*rtld_fini) (void),
        void (*stack_end)
        );

int __libc_start_main(
        int *(main) (int, char **, char **),
        int argc,
        char ** ubp_av,
        void (*init) (void),
        void (*fini) (void),
        void (*rtld_fini) (void),
        void *stack_end)
        __attribute__ ((noreturn));

int __libc_start_main(
        int *(main) (int, char **, char **),
        int argc,
        char ** ubp_av,
        void (*init) (void),
        void (*fini) (void),
        void (*rtld_fini) (void),
        void *stack_end) {

    T_libc_start_main orig_libc_start_main = (T_libc_start_main)dlsym(RTLD_NEXT, "__libc_start_main");
    s_original_open = (open_t)dlsym(RTLD_NEXT, "open64");
    s_original_close = (close_t)dlsym(RTLD_NEXT, "close64");
    g_original_ioctl = (ioctl_t)dlsym(RTLD_NEXT, "ioctl");
    s_original_write = (write_t)dlsym(RTLD_NEXT, "write");
    s_original_sigaction = (sigaction_t)dlsym(RTLD_NEXT, "sigaction");

    printf("Starting QEMU...\n");
    (*orig_libc_start_main)(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

    exit(1); // This is never reached
}
