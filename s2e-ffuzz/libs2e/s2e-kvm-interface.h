///
/// Copyright (C) 2015-2016, Cyberhaven, Inc
/// All rights reserved. Proprietary and confidential.
///
/// Distributed under the terms of S2E-LICENSE
///

#ifndef SE_KVM_INTERFACE

#define SE_KVM_INTERFACE

#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include <cpu/kvm.h>

typedef int (*open_t)(const char *pathname, int flags, mode_t mode);
typedef int (*close_t)(int fd);
typedef int (*ioctl_t)(int d, int request, ...);
typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);

typedef int (*sigaction_t)(int signum, const struct sigaction *act,
                    struct sigaction *oldact);


extern ioctl_t g_original_ioctl;

extern int g_kvm_fd;
extern int g_kvm_vm_fd;
extern int g_kvm_vcpu;


extern uint64_t g_apic_base;

struct se_qemu_interface_t;
void init_s2e_qemu_interface(struct se_qemu_interface_t *sqi);

/****************************************************/

int s2e_kvm_get_api_version(void);
int s2e_kvm_check_extension(int kvm_fd, int capability);
int s2e_kvm_create_vm(int kvm_fd);
int s2e_kvm_get_vcpu_mmap_size(void);
int s2e_kvm_get_msr_index_list(int kvm_fd, struct kvm_msr_list *list);
int s2e_kvm_get_supported_cpuid(int kvm_fd, struct kvm_cpuid2 *cpuid);

/**** vm ioctl handlers *******/

int s2e_kvm_vm_set_tss_addr(int vm_fd, uint64_t tss_addr);
int s2e_kvm_vm_create_vcpu(int vm_fd);
int s2e_kvm_vm_set_user_memory_region(int vm_fd, struct kvm_userspace_memory_region *region);
int s2e_kvm_vm_set_clock(int vm_fd, struct kvm_clock_data *clock);
int s2e_kvm_vm_enable_cap(int vm_fd, struct kvm_enable_cap *cap);
int s2e_kvm_vm_ioeventfd(int vm_fd, struct kvm_ioeventfd *event);
int s2e_kvm_vm_set_identity_map_addr(int vm_fd, uint64_t addr);
int s2e_kvm_vm_get_dirty_log(int vm_fd, struct kvm_dirty_log *log);
int s2e_kvm_vm_mem_rw(int vm_fd, struct kvm_mem_rw *mem);

/**** vcpu ioctl handlers *******/

int s2e_kvm_vcpu_get_clock(int vcpu_fd, struct kvm_clock_data *clock);
int s2e_kvm_vcpu_set_cpuid2(int vcpu_fd, struct kvm_cpuid2 *cpuid);
int s2e_kvm_vcpu_set_signal_mask(int vcpu_fd, struct kvm_signal_mask *mask);
int s2e_kvm_vcpu_set_regs(int vcpu_fd, struct kvm_regs *regs);
int s2e_kvm_vcpu_set_fpu(int vcpu_fd, struct kvm_fpu *fpu);
int s2e_kvm_vcpu_set_sregs(int vcpu_fd, struct kvm_sregs *sregs);
int s2e_kvm_vcpu_set_msrs(int vcpu_fd, struct kvm_msrs *msrs);
int s2e_kvm_vcpu_set_mp_state(int vcpu_fd, struct kvm_mp_state *mp);

int s2e_kvm_vcpu_get_regs(int vcpu_fd, struct kvm_regs *regs);
int s2e_kvm_vcpu_get_fpu(int vcpu_fd, struct kvm_fpu *fpu);
int s2e_kvm_vcpu_get_sregs(int vcpu_fd, struct kvm_sregs *sregs);
int s2e_kvm_vcpu_get_msrs(int vcpu_fd, struct kvm_msrs *msrs);
int s2e_kvm_vcpu_get_mp_state(int vcpu_fd, struct kvm_mp_state *mp);

int s2e_kvm_vcpu_run(int vcpu_fd);
int s2e_kvm_vcpu_interrupt(int vcpu_fd, struct kvm_interrupt *interrupt);

void s2e_kvm_signal_handler(int signum);

/****************************************************/
/* Tracing api */

int handle_kvm_ioctl_trace(int fd, int request, uint64_t arg1);
int handle_kvm_vm_ioctl_trace(int fd, int request, uint64_t arg1);
int handle_kvm_vcpu_ioctl_trace(int fd, int request, uint64_t arg1);

void trace_s2e_kvm_run(struct kvm_run *run, int ret);
void trace_s2e_kvm_set_user_memory_region(struct kvm_userspace_memory_region *region);

uint64_t s2e_kvm_mmio_read(uint64_t addr, unsigned size);
void s2e_kvm_mmio_write(uint64_t addr, uint64_t data, unsigned size);

/****************************************************/
/* Debugging flags */

//#define SE_KVM_DEBUG_IRQ
//#define SE_KVM_DEBUG_IO
//#define SE_KVM_DEBUG_MMIO
//#define SE_KVM_DEBUG_APIC
//#define SE_KVM_DEBUG_HLT
//#define SE_KVM_DEBUG_CPUID
//#define SE_KVM_DEBUG_MEMORY
//#define SE_KVM_DEBUG_INTERFACE


#endif
