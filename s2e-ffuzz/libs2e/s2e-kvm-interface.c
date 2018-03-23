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
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

#define BIT(n) (1 << (n))
#include <cpu/kvm.h>

#include "s2e-kvm-interface.h"
#include <cpu/memory.h>
#include "qemu-timer.h"
#include "qemu-log.h"
#include <cpu/ioport.h>
#include <cpu/exec.h>

#include "coroutine.h"

#ifdef CONFIG_SYMBEX
#include <s2e/s2e_qemu.h>
#endif

#include <s2e/monitor.h>

#include <cpu/ioport.h>
#include <cpu/i386/cpu.h>

extern CPUX86State *env;
extern void *g_s2e;

// Convenience variable to help debugging in gdb.
// env is present in both inside qemu and libs2e, which
// causes confusion.
CPUX86State *g_qemu_env;

#define false 0


extern int g_s2e_kvm_irq;

int g_exit_on_sti = 0;
int g_signal_pending = 0;

uint64_t g_apic_base = 0xfee00900;


static const int MAX_MEMORY_SLOTS = 32;
bool s_inside_cpuloop = false;
static int s_handling_io;

static volatile bool s_s2e_exiting = false;
static volatile bool s_s2e_timer_exited = false;

static pthread_mutex_t s_cpu_mutex;
static pthread_t s_timer_thread;

static struct cpu_io_funcs_t s_io;


static void* s2e_timer_cb(void *param)
{
    while (!s_s2e_exiting) {
        #ifdef CONFIG_SYMBEX
        if (!pthread_mutex_trylock(&s_cpu_mutex)) {
            if (!s_handling_io) {
                qemu_run_all_timers();
            }
            pthread_mutex_unlock(&s_cpu_mutex);
        }
        #endif

        // XXX: this must be fixed, we need to figure
        // out how to exit the cpu loop only when needed,
        // and not force it every 10ms. A higher value (e.g., 100ms)
        // will slow down the guest.
        usleep(10 * 1000); // Sleep 10ms
        g_signal_pending = 1;
        cpu_exit(env);
    }

    s_s2e_timer_exited = true;
    return NULL;
}


#ifdef CONFIG_SYMBEX
#include <s2e/s2e_config.h>
#include <tcg/tcg-llvm.h>

const char *g_s2e_config_file = NULL;
const char *g_s2e_output_dir;
const char *g_s2e_shared_dir = NULL;
int g_execute_always_klee = 0;
int g_s2e_verbose = 0;
int g_s2e_max_processes = 1;

static void s2e_terminate_timer_thread()
{
    s_s2e_exiting = true;
    // XXX: can't wait for the thread to exit because
    // s2e_cleanup may be called as part of atexit() from
    // one of the plugins (e.g., if the plugin does exit()
    // from the timer thread).
    // while (!s_s2e_timer_exited);
}

static void s2e_cleanup(void)
{
    s2e_terminate_timer_thread();

    if (g_s2e) {
        monitor_close();
        s2e_close();
        g_s2e = NULL;
    }
}

static void s2e_init(void)
{
    tcg_llvm_ctx = tcg_llvm_initialize();

    g_s2e_config_file = getenv("S2E_CONFIG");

    if (!g_s2e_config_file) {
        fprintf(stderr, "Warning: S2E_CONFIG environment variable was not specified, "
                "using the default (empty) config file\n");
    }

    g_s2e_output_dir = getenv("S2E_OUTPUT_DIR");

    int argc = 0;
    char **argv = {NULL};

    if (monitor_init() < 0) {
        exit(-1);
    }

    int unbuffered_stream = 0;
    const char *us = getenv("S2E_UNBUFFERED_STREAM");
    if (us && us[0] == '1') {
        unbuffered_stream = 1;
    }

    s2e_initialize(argc, argv, tcg_llvm_ctx,
                   g_s2e_config_file, g_s2e_output_dir,
                   unbuffered_stream,
                   g_s2e_verbose, g_s2e_max_processes);

    s2e_create_initial_state();

    atexit(s2e_cleanup);
}

#endif


/**** /dev/kvm ioctl handlers *******/

int s2e_kvm_get_api_version(void)
{
    return KVM_API_VERSION;
}

int s2e_kvm_check_extension(int kvm_fd, int capability)
{
    switch (capability) {
        case KVM_CAP_NR_MEMSLOTS: {
            return MAX_MEMORY_SLOTS;
        } break;

        case KVM_CAP_MP_STATE:
        case KVM_CAP_EXT_CPUID:
        case KVM_CAP_SET_TSS_ADDR:
        case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
        case KVM_CAP_USER_MEMORY:
        case KVM_CAP_NR_VCPUS:
        case KVM_CAP_MAX_VCPUS:
        case KVM_CAP_MEM_RW:  /* libs2e-specific call */
            return 1;

        default:
            //return s_original_ioctl(fd, request, arg1);
            #ifdef SE_KVM_DEBUG_INTERFACE
            printf("Unsupported cap %x\n", capability);
            #endif
            return -1;
    }
}

///
/// \brief s2e_kvm_init_log_level initializes the qemu log level.
///
/// This is the same as the -d switch from vanilla QEMU.
///
static void s2e_kvm_init_log_level()
{
    loglevel = 0;
    const char *qemu_log_level = getenv("QEMU_LOG_LEVEL");
    if (qemu_log_level) {
        loglevel = cpu_str_to_log_mask(qemu_log_level);
    }

    const char *qemu_log_file = getenv("QEMU_LOG_FILE");
    if (qemu_log_file) {
        logfile = fopen(qemu_log_file, "w");
        if (!logfile) {
            printf("Could not open log file %s\n", qemu_log_file);
            exit(-1);
        }
    } else {
        logfile = stdout;
    }
}

static int s2e_kvm_init_timer_thread(void)
{
    int ret;
    pthread_attr_t attr;

    ret = pthread_attr_init(&attr);
    if (ret < 0) {
        fprintf(stderr, "Could not init thread attributes\n");
        goto err1;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret < 0) {
        fprintf(stderr, "Could not set detached state for thread\n");
        goto err1;
    }

    ret = pthread_create(&s_timer_thread, &attr, s2e_timer_cb, NULL);
    if (ret < 0) {
        fprintf(stderr, "could not create timer thread\n");
        goto err1;
    }

    pthread_attr_destroy(&attr);

    err1:
    return ret;
}

static int s2e_kvm_init_cpu_mutex(void)
{
    int ret = pthread_mutex_init(&s_cpu_mutex, NULL);
    if (ret < 0) {
        fprintf(stderr, "Could not init mutex\n");
    }
    return ret;
}

int s2e_kvm_create_vm(int kvm_fd)
{
    /* Reserve a dummy file descriptor */
    int fd = open("/dev/null", O_RDWR | O_CREAT | O_TRUNC, 0700);
    if (fd < 0) {
        goto err1;
    }

#ifdef CONFIG_SYMBEX
    init_s2e_qemu_interface(&g_sqi);
#endif

    cpu_register_io(&s_io);
    tcg_exec_init(0);
    s2e_kvm_init_log_level();

    x86_cpudef_setup();

    /* We want the default QEMU CPU, not the KVM one. */
    g_qemu_env = env = cpu_x86_init("qemu64");
    if (!env) {
        printf("Could not create cpu\n");
        goto err2;
    }

    g_qemu_env->size = sizeof(*g_qemu_env);

    if (s2e_kvm_init_cpu_mutex() < 0) {
        exit(-1);
    }

    init_clocks();

    if (s2e_kvm_init_timer_thread() < 0) {
        exit(-1);
    }

#ifdef CONFIG_SYMBEX
    g_s2e_shared_dir = getenv("S2E_SHARED_DIR");
    if (!g_s2e_shared_dir) {
      fprintf(stderr, "Warning: S2E_SHARED_DIR environment variable was not specified, "
                        "using %s\n", CONFIG_QEMU_DATADIR);
      g_s2e_shared_dir = CONFIG_QEMU_DATADIR;
    }

    s2e_init();

    // Call it twice, because event pointers are only known
    // after s2e is inited.
    init_s2e_qemu_interface(&g_sqi);

    s2e_register_cpu(env);

    s2e_init_device_state();
    s2e_init_timers();

    s2e_initialize_execution(g_execute_always_klee);
    s2e_register_dirty_mask((uint64_t)get_ram_list_phys_dirty(), last_ram_offset() >> TARGET_PAGE_BITS);
    s2e_on_initialization_complete();
#endif

    do_cpu_init(env);


    return fd;

    err2: close(fd);
    err1: return fd;
}

int s2e_kvm_get_vcpu_mmap_size(void)
{
    return 0x10000; /* Some magic value */
}

static uint32_t s_msr_list [] = {
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_IA32_APICBASE,
    MSR_EFER,
    MSR_STAR,
    MSR_PAT,
    MSR_VM_HSAVE_PA,
    #ifdef TARGET_X86_64
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_FMASK,
    MSR_FSBASE,
    MSR_GSBASE,
    MSR_KERNELGSBASE,
    #endif
    MSR_MTRRphysBase(0),
    MSR_MTRRphysBase(1),
    MSR_MTRRphysBase(2),
    MSR_MTRRphysBase(3),
    MSR_MTRRphysBase(4),
    MSR_MTRRphysBase(5),
    MSR_MTRRphysBase(6),
    MSR_MTRRphysBase(7),
    MSR_MTRRphysMask(0),
    MSR_MTRRphysMask(1),
    MSR_MTRRphysMask(2),
    MSR_MTRRphysMask(3),
    MSR_MTRRphysMask(4),
    MSR_MTRRphysMask(5),
    MSR_MTRRphysMask(6),
    MSR_MTRRphysMask(7),
    MSR_MTRRfix64K_00000,
    MSR_MTRRfix16K_80000,
    MSR_MTRRfix16K_A0000,
    MSR_MTRRfix4K_C0000,
    MSR_MTRRfix4K_C8000,
    MSR_MTRRfix4K_D0000,
    MSR_MTRRfix4K_D8000,
    MSR_MTRRfix4K_E0000,
    MSR_MTRRfix4K_E8000,
    MSR_MTRRfix4K_F0000,
    MSR_MTRRfix4K_F8000,
    MSR_MTRRdefType,
    MSR_MCG_STATUS,
    MSR_MCG_CTL,
    MSR_TSC_AUX,
    MSR_IA32_MISC_ENABLE,
    MSR_MC0_CTL,
    MSR_MC0_STATUS,
    MSR_MC0_ADDR,
    MSR_MC0_MISC
};

int s2e_kvm_get_msr_index_list(int kvm_fd, struct kvm_msr_list *list)
{
    if (list->nmsrs == 0) {
        list->nmsrs = sizeof(s_msr_list) / sizeof(s_msr_list[0]);
    } else {
        for (int i = 0; i < list->nmsrs; ++i) {
            list->indices[i] = s_msr_list[i];
        }
    }

    return 0;
}

/* Array of valid (function, index) entries */
static uint32_t s_cpuid_entries[][2] = {
    {0, -1},
    {1, -1},
    {2, -1},
    {4, 0},
    {4, 1},
    {4, 2},
    {4, 3},
    {5, -1},
    {6, -1},
    {7, -1},
    {9, -1},
    {0xa, -1},
    {0xd, -1},
    {0x80000000, -1},
    {0x80000001, -1},
    {0x80000002, -1},
    {0x80000003, -1},
    {0x80000004, -1},
    {0x80000005, -1},
    {0x80000006, -1},
    {0x80000008, -1},
    {0x8000000a, -1},
    {0xc0000000, -1},
    {0xc0000001, -1},
    {0xc0000002, -1},
    {0xc0000003, -1},
    {0xc0000004, -1}
};

#ifdef SE_KVM_DEBUG_CPUID
static void print_cpuid2(struct kvm_cpuid_entry2 *e)
{
    printf("cpuid function=%#010"PRIx32" index=%#010"PRIx32" flags=%#010"PRIx32
           " eax=%#010"PRIx32
           " ebx=%#010"PRIx32
           " ecx=%#010"PRIx32
           " edx=%#010"PRIx32"\n", e->function, e->index, e->flags,
           e->eax, e->ebx, e->ecx, e->edx);
}
#endif

int s2e_kvm_get_supported_cpuid(int kvm_fd, struct kvm_cpuid2 *cpuid)
{
    #ifdef SE_KVM_DEBUG_CPUID
    printf("%s\n", __FUNCTION__);
    #endif

    unsigned int nentries = sizeof(s_cpuid_entries) / sizeof(s_cpuid_entries[0]);
    if (cpuid->nent < nentries) {
        errno = E2BIG;
        return -1;
    } else if (cpuid->nent >= nentries) {
        cpuid->nent = nentries;
        //errno = ENOMEM;
        //return -1;
    }

    for (unsigned i = 0; i < nentries; ++i) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        cpu_x86_cpuid(env, s_cpuid_entries[i][0], s_cpuid_entries[i][1],
                &e->eax, &e->ebx, &e->ecx, &e->edx);

        e->flags = 0;
        e->index = 0;
        if (s_cpuid_entries[i][1] != -1) {
            e->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
            e->index = s_cpuid_entries[i][1];
        }
        e->function = s_cpuid_entries[i][0];

        #ifdef SE_KVM_DEBUG_CPUID
        print_cpuid2(e);
        #endif
    }

    return 0;
}

/**** vm ioctl handlers *******/

int s2e_kvm_vm_set_tss_addr(int vm_fd, uint64_t tss_addr)
{
    printf("Setting tss addr %#"PRIx64" not implemented yet\n", tss_addr);
    return 0;
}


struct kvm_run *s_kvm_vcpu_buffer;
static Coroutine *s_kvm_cpu_coroutine;

uint64_t s2e_kvm_mmio_read(target_phys_addr_t addr, unsigned size)
{
    s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_MMIO;
    s_kvm_vcpu_buffer->mmio.is_write = 0;
    s_kvm_vcpu_buffer->mmio.phys_addr = addr;
    s_kvm_vcpu_buffer->mmio.len = size;

    uint8_t *dataptr = s_kvm_vcpu_buffer->mmio.data;

    qemu_coroutine_yield();

    uint64_t ret;
    switch (size) {
        case 1: ret = *(uint8_t*) dataptr; break;
        case 2: ret = *(uint16_t*) dataptr;  break;
        case 4: ret = *(uint32_t*) dataptr; break;
        default: assert(false && "Can't get here");
    }

    #ifdef SE_KVM_DEBUG_MMIO
    unsigned print_addr = 0;
    #ifdef SE_KVM_DEBUG_APIC
    if (addr >= 0xf0000000) print_addr = 1;
    #endif
    if (print_addr) {
        printf("mmior%d[%x]=%x\n", size, addr, ret);
        printf("env->mflags=%x hflags=%x hflags2=%x\n",
               env->mflags, env->hflags, env->hflags2);
    }
    #endif
    return ret;

}

void s2e_kvm_mmio_write(target_phys_addr_t addr, uint64_t data, unsigned size)
{
    s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_MMIO;
    s_kvm_vcpu_buffer->mmio.is_write = 1;
    s_kvm_vcpu_buffer->mmio.phys_addr = addr;
    s_kvm_vcpu_buffer->mmio.len = size;

    uint8_t *dataptr = s_kvm_vcpu_buffer->mmio.data;

    #ifdef SE_KVM_DEBUG_MMIO
    unsigned print_addr = 0;
    #ifdef SE_KVM_DEBUG_APIC
    if (addr >= 0xf0000000) print_addr = 1;
    #endif

    if (print_addr) {
        printf("mmiow%d[%x]=%x\n", size, addr, data);
        printf("env->mflags=%x hflags=%x hflags2=%x\n",
               env->mflags, env->hflags, env->hflags2);
    }
    #endif

    switch (size) {
        case 1: *(uint8_t*) dataptr = data; break;
        case 2: *(uint16_t*) dataptr = data; break;
        case 4: *(uint32_t*) dataptr = data; break;
        default: assert(false && "Can't get here");
    }

    qemu_coroutine_yield();
}

uint64_t s2e_kvm_ioport_read(pio_addr_t addr, unsigned size)
{
    s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IO;
    s_kvm_vcpu_buffer->io.direction = KVM_EXIT_IO_IN;
    s_kvm_vcpu_buffer->io.size = size;
    s_kvm_vcpu_buffer->io.port = addr;
    s_kvm_vcpu_buffer->io.count = 1;

    unsigned offs = sizeof(struct kvm_run);
    uint8_t *dataptr = (uint8_t *)s_kvm_vcpu_buffer;
    dataptr += offs;

    s_kvm_vcpu_buffer->io.data_offset = offs;

    qemu_coroutine_yield();

    uint64_t ret;
    switch (size) {
        case 1: ret = *(uint8_t*) dataptr; break;
        case 2: ret = *(uint16_t*) dataptr;  break;
        case 4: ret = *(uint32_t*) dataptr; break;
        default: assert(false && "Can't get here");
    }

    #ifdef SE_KVM_DEBUG_IO
    printf("ior%d[%x]=%x\n", size, addr, ret);
    printf("env->mflags=%x hflags=%x hflags2=%x\n",
           env->mflags, env->hflags, env->hflags2);
    #endif

    return ret;
}

void s2e_kvm_ioport_write(pio_addr_t addr, uint64_t data, unsigned size)
{
    s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IO;
    s_kvm_vcpu_buffer->io.direction = KVM_EXIT_IO_OUT;
    s_kvm_vcpu_buffer->io.size = size;
    s_kvm_vcpu_buffer->io.port = addr;
    s_kvm_vcpu_buffer->io.count = 1;


    unsigned offs = sizeof(struct kvm_run);
    uint8_t *dataptr = (uint8_t *)s_kvm_vcpu_buffer;
    dataptr += offs;

    s_kvm_vcpu_buffer->io.data_offset = offs;

    switch (size) {
        case 1: *(uint8_t*) dataptr = data; break;
        case 2: *(uint16_t*) dataptr = data; break;
        case 4: *(uint32_t*) dataptr = data; break;
        default: assert(false && "Can't get here");
    }

    #ifdef SE_KVM_DEBUG_IO
    printf("iow%d[%x]=%x\n", size, addr, data);
    printf("env->mflags=%x hflags=%x hflags2=%x\n",
           env->mflags, env->hflags, env->hflags2);
    #endif

    qemu_coroutine_yield();
}

static struct cpu_io_funcs_t s_io = {
    .io_read = s2e_kvm_ioport_read,
    .io_write = s2e_kvm_ioport_write,
    .mmio_read = s2e_kvm_mmio_read,
    .mmio_write = s2e_kvm_mmio_write,
};

int s2e_kvm_vm_create_vcpu(int vm_fd)
{
    /* User-space can use the vcpu descriptor to mmap it */
    int fd = shm_open("s2e-kvm-cpu", O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        goto err1;
    }

    int flags = MAP_SHARED;
    size_t size = s2e_kvm_get_vcpu_mmap_size();

    if (ftruncate(fd, size) < 0) {
        goto err2;
    }

    s_kvm_vcpu_buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, fd, 0);

    cpu_exec_init_all();

    return fd;
    err2: close(fd);
    err1: return -1;
}


int s2e_kvm_vm_set_user_memory_region(int vm_fd, struct kvm_userspace_memory_region *region)
{
    tlb_flush(env, 1);
    mem_desc_unregister(region->slot);
    mem_desc_register(region);
    return 0;
}

uint64_t g_clock_start = 0;
uint64_t g_clock_offset = 0;
int s2e_kvm_vm_set_clock(int vm_fd, struct kvm_clock_data *clock)
{
    g_clock_start = clock->clock;
    g_clock_offset = cpu_get_real_ticks();
    return 0;
}

int s2e_kvm_vm_enable_cap(int vm_fd, struct kvm_enable_cap *cap)
{
    printf("enabling not supported capability %d\n", cap->cap);
    errno = 1;
    return -1;
}

int s2e_kvm_vm_ioeventfd(int vm_fd, struct kvm_ioeventfd *event)
{
    printf("kvm_ioeventd datamatch=%#llx addr=%#llx len=%d fd=%d flags=%#"PRIx32"\n",
           event->datamatch, event->addr, event->len, event->fd, event->flags);
    return 0;

    assert(false && "Not implemented");
}

int s2e_kvm_vm_set_identity_map_addr(int vm_fd, uint64_t addr)
{
    assert(false && "Not implemented");
}

/**
 * Seems to be only used by vga so far, should be ok to return that
 * all pages are dirty, without looking at them.
 */
int s2e_kvm_vm_get_dirty_log(int vm_fd, struct kvm_dirty_log *log)
{
    const MemoryDesc *r = mem_desc_get_slot(log->slot);

    unsigned bits = r->kvm.memory_size / TARGET_PAGE_SIZE;
    unsigned bytes = bits / 8;
    memset(log->dirty_bitmap, -1, bytes);
    return 0;
}

int s2e_kvm_vm_mem_rw(int vm_fd, struct kvm_mem_rw *mem)
{
    assert(!mem->is_dest_guest_phys && !mem->is_source_guest_phys);

#if defined(CONFIG_SYMBEX) && defined(CONFIG_SYMBEX_MP)
    abort(); // Not implemented
#if 0
    pthread_mutex_lock(&s_cpu_mutex);

    if (mem->is_write) {
        for (unsigned i = 0; i < mem->length; ++i) {
            stb_raw((void*)(mem->dest+i), *(uint8_t*)(mem->source + i));
        }

        ram_addr_t addr1 = qemu_ram_addr_from_host_nofail((void*) mem->dest);
        uint64_t access_len = mem->length;
        while (access_len) {
            unsigned l;
            l = TARGET_PAGE_SIZE;
            if (l > access_len)
                l = access_len;
            if (!cpu_physical_memory_is_dirty(addr1)) {
                /* invalidate code */
                tb_invalidate_phys_page_range(addr1, addr1 + l, 0);
                /* set dirty bit */
                cpu_physical_memory_set_dirty_flags(
                    addr1, (0xff & ~CODE_DIRTY_FLAG));
            }
            addr1 += l;
            access_len -= l;
        }
    } else {
        for (unsigned i = 0; i < mem->length; ++i) {
            *(uint8_t*)(mem->dest+i) = ldub_raw((uint8_t*)(mem->source + i));
        }
    }
    pthread_mutex_unlock(&s_cpu_mutex);
#endif
#else
    memcpy((void*) mem->dest, (void *) mem->source, mem->length);
#endif

    return 0;
}

/**** vcpu ioctl handlers *******/

int s2e_kvm_vcpu_get_clock(int vcpu_fd, struct kvm_clock_data *clock)
{
    assert(false && "Not implemented");
}

int s2e_kvm_vcpu_set_cpuid2(int vcpu_fd, struct kvm_cpuid2 *cpuid)
{
    /**
     * QEMU insists on using host cpuid flags when running in KVM mode.
     * We want to use those set in DBT mode instead.
     * TODO: for now, we have no way to configure custom flags.
     * Snapshots will not work if using anything other that defaults.
     */
    return 0;
}

static unsigned s_s2e_kvm_sigmask_size;

static union {
    sigset_t s_sigsets;
    uint8_t bytes[32];
} s_s2e_kvm_sigmask;

int s2e_kvm_vcpu_set_signal_mask(int vcpu_fd, struct kvm_signal_mask *mask)
{
    //TODO: block the specified signals
    printf("Not implemented %s\n", __FUNCTION__);
    s_s2e_kvm_sigmask_size = mask->len;
    for (unsigned i = 0; i < mask->len; ++i) {
        printf("  signals %#04x\n", mask->sigset[i]);
        s_s2e_kvm_sigmask.bytes[i] = mask->sigset[i];
    }
    return 0;
}

int s2e_kvm_vcpu_set_regs(int vcpu_fd, struct kvm_regs *regs)
{
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_ESP] = regs->rsp;
    env->regs[R_EBP] = regs->rbp;

#ifdef TARGET_X86_64
    env->regs[8] = regs->r8;
    env->regs[9] = regs->r9;
    env->regs[10] = regs->r10;
    env->regs[11] = regs->r11;
    env->regs[12] = regs->r12;
    env->regs[13] = regs->r13;
    env->regs[14] = regs->r14;
    env->regs[15] = regs->r15;
#endif

    env->eip = regs->rip;
    //cpu_set_eflags(env, regs->rflags);
    return 0;
}

int s2e_kvm_vcpu_set_fpu(int vcpu_fd, struct kvm_fpu *fpu)
{
    env->fpstt = (fpu->fsw >> 11) & 7;
    env->fpus = fpu->fsw;
    env->fpuc = fpu->fcw;
    env->fpop = fpu->last_opcode;
    env->fpip = fpu->last_ip;
    env->fpdp = fpu->last_dp;
    for (unsigned i = 0; i < 8; ++i) {
        env->fptags[i] = !((fpu->ftwx >> i) & 1);
    }
    memcpy(env->fpregs, fpu->fpr, sizeof env->fpregs);
    memcpy(env->xmm_regs, fpu->xmm, sizeof env->xmm_regs);
    env->mxcsr = fpu->mxcsr;
    return 0;
}

static void set_qemu_segment(SegmentCache *qemu_seg, const struct kvm_segment *kvm_seg)
{
    qemu_seg->selector = kvm_seg->selector;
    qemu_seg->base = kvm_seg->base;
    qemu_seg->limit = kvm_seg->limit;
    qemu_seg->flags = (kvm_seg->type << DESC_TYPE_SHIFT) |
                 (kvm_seg->present * DESC_P_MASK) |
                 (kvm_seg->dpl << DESC_DPL_SHIFT) |
                 (kvm_seg->db << DESC_B_SHIFT) |
                 (kvm_seg->s * DESC_S_MASK) |
                 (kvm_seg->l << DESC_L_SHIFT) |
                 (kvm_seg->g * DESC_G_MASK) |
                 (kvm_seg->avl * DESC_AVL_MASK);
}

///
/// \brief s2e_kvm_compute_hflags gathers info scattered across different
/// cpu registers into the hflags register.
///
/// This function pastes together code from the following functions:
/// - cpu_x86_load_seg_cache
/// - cpu_x86_update_cr0
/// - cpu_x86_update_cr4

/// \param env the cpu state
/// \return the value for hflags
///
static uint32_t s2e_kvm_compute_hflags(const CPUArchState *env)
{
    uint32_t hflags = 0;

    /* Update CR0 flags */
    target_ulong pe_state = (env->cr[0] & CR0_PE_MASK);
    hflags |= pe_state << HF_PE_SHIFT;
    hflags |= (pe_state ^ 1) << HF_ADDSEG_SHIFT;
    hflags |= (hflags & ~(HF_MP_MASK | HF_EM_MASK | HF_TS_MASK)) |
        ((env->cr[0] << (HF_MP_SHIFT - 1)) & (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK));

    /* Update CR4 flags */
    if (env->cr[4] & CR4_OSFXSR_MASK) {
        hflags |= HF_OSFXSR_MASK;
    } else {
        hflags &= ~HF_OSFXSR_MASK;
    }

    /* Update CPL */
    hflags |= (env->segs[R_CS].flags >> DESC_DPL_SHIFT) & HF_CPL_MASK;

    /* Update from mflags */
    hflags |= env->mflags & (HF_TF_MASK | HF_IOPL_MASK | HF_VM_MASK);

    if (env->efer & MSR_EFER_LMA) {
        hflags |= HF_LMA_MASK;
    }
    if (env->efer & MSR_EFER_SVME) {
        hflags |= HF_SVME_MASK;
    }

#ifdef TARGET_X86_64
    if ((hflags & HF_LMA_MASK) && (env->segs[R_CS].flags & DESC_L_MASK)) {
        /* long mode */
        hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
    } else
#endif
    {
        hflags |= (env->segs[R_CS].flags & DESC_B_MASK)
            >> (DESC_B_SHIFT - HF_CS32_SHIFT);
    }


    hflags |= (env->segs[R_SS].flags & DESC_B_MASK)
        >> (DESC_B_SHIFT - HF_SS32_SHIFT);

    if (hflags & HF_CS64_MASK) {
        /* zero base assumed for DS, ES and SS in long mode */
    } else if (!(env->cr[0] & CR0_PE_MASK) ||
            (env->mflags & VM_MASK) ||
            !(hflags & HF_CS32_MASK)) {
        /* XXX: try to avoid this test. The problem comes from the
                   fact that is real mode or vm86 mode we only modify the
                   'base' and 'selector' fields of the segment cache to go
                   faster. A solution may be to force addseg to one in
                   translate-i386.c. */
        hflags |= HF_ADDSEG_MASK;
    } else {
        hflags |= ((env->segs[R_DS].base |
                    env->segs[R_ES].base |
                    env->segs[R_SS].base) != 0) << HF_ADDSEG_SHIFT;
    }

    hflags = (env->hflags &
                   ~(HF_SS32_MASK | HF_ADDSEG_MASK)) | hflags;

    return hflags;
}

int s2e_kvm_vcpu_set_sregs(int vcpu_fd, struct kvm_sregs *sregs)
{
    //XXX: what about the interrupt bitmap?
    set_qemu_segment(&env->segs[R_CS], &sregs->cs);
    set_qemu_segment(&env->segs[R_DS], &sregs->ds);
    set_qemu_segment(&env->segs[R_ES], &sregs->es);
    set_qemu_segment(&env->segs[R_FS], &sregs->fs);
    set_qemu_segment(&env->segs[R_GS], &sregs->gs);
    set_qemu_segment(&env->segs[R_SS], &sregs->ss);

    set_qemu_segment(&env->tr, &sregs->tr);
    set_qemu_segment(&env->ldt, &sregs->ldt);

    env->idt.limit = sregs->idt.limit;
    env->idt.base = sregs->idt.base;
    env->gdt.limit = sregs->gdt.limit;
    env->gdt.base = sregs->gdt.base;

    env->cr[0] = sregs->cr0;
    env->cr[2] = sregs->cr2;
    env->cr[3] = sregs->cr3;
    env->cr[4] = sregs->cr4;
    env->v_tpr = sregs->cr8;

    if (sregs->apic_base) {
        g_apic_base = sregs->apic_base;
    }

    env->efer = sregs->efer;
    env->hflags = s2e_kvm_compute_hflags(env);

    return 0;
}

void helper_wrmsr_v(target_ulong index, uint64_t val);
int s2e_kvm_vcpu_set_msrs(int vcpu_fd, struct kvm_msrs *msrs)
{
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        helper_wrmsr_v(msrs->entries[i].index, msrs->entries[i].data);
    }
    return 0;
}

int s2e_kvm_vcpu_set_mp_state(int vcpu_fd, struct kvm_mp_state *mp)
{
    /* Only needed when using an irq chip */
    return 0;
}

int s2e_kvm_vcpu_get_regs(int vcpu_fd, struct kvm_regs *regs)
{
    regs->rax = env->regs[R_EAX];
    regs->rbx = env->regs[R_EBX];
    regs->rcx = env->regs[R_ECX];
    regs->rdx = env->regs[R_EDX];
    regs->rsi = env->regs[R_ESI];
    regs->rdi = env->regs[R_EDI];
    regs->rsp = env->regs[R_ESP];
    regs->rbp = env->regs[R_EBP];

#ifdef TARGET_X86_64
    regs->r8 = env->regs[8];
    regs->r9 = env->regs[9];
    regs->r10 = env->regs[10];
    regs->r11 = env->regs[11];
    regs->r12 = env->regs[12];
    regs->r13 = env->regs[13];
    regs->r14 = env->regs[14];
    regs->r15 = env->regs[15];
#endif

    regs->rip = env->eip;


    //XXX: This function may be called in the middle of the execution.
    //Figure out how to put the system in a consistent state
    if (!s_inside_cpuloop) {
        regs->rflags = cpu_get_eflags(env);
    }

    return 0;
}

int s2e_kvm_vcpu_get_fpu(int vcpu_fd, struct kvm_fpu *fpu)
{
    int i;

    fpu->fsw = env->fpus & ~(7 << 11);
    fpu->fsw |= (env->fpstt & 7) << 11;
    fpu->fcw = env->fpuc;
    fpu->last_opcode = env->fpop;
    fpu->last_ip = env->fpip;
    fpu->last_dp = env->fpdp;
    for (i = 0; i < 8; ++i) {
        fpu->ftwx |= (!env->fptags[i]) << i;
    }
    memcpy(fpu->fpr, env->fpregs, sizeof env->fpregs);
    memcpy(fpu->xmm, env->xmm_regs, sizeof env->xmm_regs);
    fpu->mxcsr = env->mxcsr;

    return 0;
}

static void get_qemu_segment(struct kvm_segment *kvm_seg, const SegmentCache *qemu_seg)
{
    unsigned flags = qemu_seg->flags;
    kvm_seg->selector = qemu_seg->selector;
    kvm_seg->base = qemu_seg->base;
    kvm_seg->limit = qemu_seg->limit;
    kvm_seg->type = (flags >> DESC_TYPE_SHIFT) & 15;
    kvm_seg->present = (flags & DESC_P_MASK) != 0;
    kvm_seg->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    kvm_seg->db = (flags >> DESC_B_SHIFT) & 1;
    kvm_seg->s = (flags & DESC_S_MASK) != 0;
    kvm_seg->l = (flags >> DESC_L_SHIFT) & 1;
    kvm_seg->g = (flags & DESC_G_MASK) != 0;
    kvm_seg->avl = (flags & DESC_AVL_MASK) != 0;
    kvm_seg->unusable = 0;
    kvm_seg->padding = 0;
}

static void get_v8086_segment(struct kvm_segment *kvm_seg, const SegmentCache *qemu_seg)
{
    kvm_seg->selector = qemu_seg->selector;
    kvm_seg->base = qemu_seg->base;
    kvm_seg->limit = qemu_seg->limit;
    kvm_seg->type = 3;
    kvm_seg->present = 1;
    kvm_seg->dpl = 3;
    kvm_seg->db = 0;
    kvm_seg->s = 1;
    kvm_seg->l = 0;
    kvm_seg->g = 0;
    kvm_seg->avl = 0;
    kvm_seg->unusable = 0;
}

int s2e_kvm_vcpu_get_sregs(int vcpu_fd, struct kvm_sregs *sregs)
{
    //XXX: what about the interrupt bitmap?

    if (env->mflags & VM_MASK) {
        get_v8086_segment(&sregs->cs, &env->segs[R_CS]);
        get_v8086_segment(&sregs->ds, &env->segs[R_DS]);
        get_v8086_segment(&sregs->es, &env->segs[R_ES]);
        get_v8086_segment(&sregs->fs, &env->segs[R_FS]);
        get_v8086_segment(&sregs->gs, &env->segs[R_GS]);
        get_v8086_segment(&sregs->ss, &env->segs[R_SS]);
    } else {
        get_qemu_segment(&sregs->cs, &env->segs[R_CS]);
        get_qemu_segment(&sregs->ds, &env->segs[R_DS]);
        get_qemu_segment(&sregs->es, &env->segs[R_ES]);
        get_qemu_segment(&sregs->fs, &env->segs[R_FS]);
        get_qemu_segment(&sregs->gs, &env->segs[R_GS]);
        get_qemu_segment(&sregs->ss, &env->segs[R_SS]);
    }

    get_qemu_segment(&sregs->tr, &env->tr);
    get_qemu_segment(&sregs->ldt, &env->ldt);

    sregs->idt.limit = env->idt.limit;
    sregs->idt.base = env->idt.base;
    memset(sregs->idt.padding, 0, sizeof sregs->idt.padding);
    sregs->gdt.limit = env->gdt.limit;
    sregs->gdt.base = env->gdt.base;
    memset(sregs->gdt.padding, 0, sizeof sregs->gdt.padding);

    sregs->cr0 = env->cr[0];
    sregs->cr2 = env->cr[2];
    sregs->cr3 = env->cr[3];
    sregs->cr4 = env->cr[4];
    sregs->cr8 = env->v_tpr;

    //XXX: not implemented
    sregs->apic_base = g_apic_base;
    sregs->cr8 = env->v_tpr;
    //sregs->cr8 = cpu_get_apic_tpr(env->apic_state);
    //sregs->apic_base = cpu_get_apic_base(env->apic_state);

    sregs->efer = env->efer;
    return 0;
}

int s2e_kvm_vcpu_get_msrs(int vcpu_fd, struct kvm_msrs *msrs)
{
    uint64_t helper_rdmsr_v(uint64_t index);

    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        msrs->entries[i].data = helper_rdmsr_v(msrs->entries[i].index);
    }
    return 0;
}

int s2e_kvm_vcpu_get_mp_state(int vcpu_fd, struct kvm_mp_state *mp)
{
    //Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}

static void coroutine_fn s2e_kvm_cpu_coroutine(void *opaque)
{
    #ifdef SE_KVM_DEBUG_IRQ
    static uint64_t prev_mflags = 0;
    #endif

    while (1) {
        pthread_mutex_lock(&s_cpu_mutex);
        assert(env->current_tb == NULL);

        //XXX: not sure if this is needed
        if (g_s2e_kvm_irq != -1) {
            if (env->interrupt_request == 0) {
                printf("Forcing IRQ\n");
            }
            env->interrupt_request |= CPU_INTERRUPT_HARD;
        }

        #ifdef SE_KVM_DEBUG_IRQ
        if (env->interrupt_request & CPU_INTERRUPT_HARD) {
            printf("Handling IRQ req=%#x hflags=%x hflags2=%#x mflags=%#x tpr=%#x sp=%d\n",
                   env->interrupt_request,
                   env->hflags, env->hflags2, env->mflags, env->v_tpr,
                   g_signal_pending);
        }
        #endif

        s_inside_cpuloop = true;

        #ifdef SE_KVM_DEBUG_IRQ
        prev_mflags = env->mflags;
        #endif

        cpu_x86_exec(env);

        #ifdef SE_KVM_DEBUG_IRQ
        bool mflags_changed = (prev_mflags != env->mflags);
        bool reqint = mflags_changed && (env->mflags & IF_MASK);
        if (mflags_changed) {
            printf("mflags changed: %lx old=%lx new=%lx reqwnd=%d\n", (uint64_t) mflags_changed, prev_mflags, env->mflags,
                   s_kvm_vcpu_buffer->request_interrupt_window);
        }
        prev_mflags = env->mflags;
        #endif

        s_inside_cpuloop = false;

        assert(env->current_tb == NULL);
        pthread_mutex_unlock(&s_cpu_mutex);

        if (g_exit_on_sti) {
            if (!s_kvm_vcpu_buffer->request_interrupt_window && !g_signal_pending) {
                continue;
            }
        } else {
            /**
             * If an interrupt has been scheduled in the meantime, don't exit.
             * Seems to hang otherwise.
             */
            if (cpu_has_work(env)) {
                continue;
            }
        }

        g_exit_on_sti = 0;
        g_signal_pending = 0;
        env->exception_index = 0;
        qemu_coroutine_yield();
        //printf("<\n");
    }
}


int s2e_kvm_vcpu_run(int vcpu_fd)
{
    if (!s_kvm_cpu_coroutine) {
        s_kvm_cpu_coroutine = qemu_coroutine_create(s2e_kvm_cpu_coroutine);
    }

    s_kvm_vcpu_buffer->exit_reason = -1;

    /**
     * QEMU does not set this when calling kvm_run, although the KVM
     * spec says it should. For now, we patch QEMU to pass the right value.
     * Eventually, we'll need to figure out how KVM handles it.
     * Having an incorrect (null) APIC base will cause the APIC to get stuck.
     */
    g_apic_base = s_kvm_vcpu_buffer->apic_base;

    env->v_tpr = s_kvm_vcpu_buffer->cr8;

    if (s_handling_io) {
        pthread_mutex_lock(&s_cpu_mutex);

        if (g_s2e_kvm_irq != -1) {
            cpu_exit(env);
        }

        s_handling_io = 0;
    }

    qemu_coroutine_enter(s_kvm_cpu_coroutine, NULL);

    //Might not be NULL if resuming from an interrupted I/O
    //assert(env->current_tb == NULL);

    s_kvm_vcpu_buffer->if_flag = (env->mflags & IF_MASK) != 0;
    s_kvm_vcpu_buffer->apic_base = g_apic_base;
    s_kvm_vcpu_buffer->cr8 = env->v_tpr;

    s_kvm_vcpu_buffer->ready_for_interrupt_injection =
            s_kvm_vcpu_buffer->if_flag &&
            (g_s2e_kvm_irq == -1);

    if (s_kvm_vcpu_buffer->exit_reason == -1) {
        if (env->halted) {
            s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_HLT;
        } else if (s_kvm_vcpu_buffer->request_interrupt_window && s_kvm_vcpu_buffer->ready_for_interrupt_injection) {
            s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
        } else {
            s_kvm_vcpu_buffer->exit_reason = KVM_EXIT_INTR;
        }
    }

    int ret = 0;
    if (s_kvm_vcpu_buffer->exit_reason == KVM_EXIT_INTR) {
        errno = EINTR;
        ret = -1;
    }

    #if defined(SE_KVM_DEBUG_HLT)
    if (s_kvm_vcpu_buffer->exit_reason == KVM_EXIT_HLT) {
        trace_s2e_kvm_run(s_kvm_vcpu_buffer, ret);
    }
    #endif


    s_handling_io = s_kvm_vcpu_buffer->exit_reason == KVM_EXIT_IO || s_kvm_vcpu_buffer->exit_reason == KVM_EXIT_MMIO;
    if (s_handling_io) {
        pthread_mutex_unlock(&s_cpu_mutex);
    }

    return ret;
}

void s2e_kvm_signal_handler(int signum)
{
    pthread_mutex_lock(&s_cpu_mutex);

    g_signal_pending = 1;

    if (env->current_tb != NULL) {
        /* We must be in the middle of an I/O instruction */
        assert(s_handling_io);
    }

    cpu_exit(env);
    pthread_mutex_unlock(&s_cpu_mutex);
}


int g_s2e_kvm_irq = -1;
int s2e_kvm_vcpu_interrupt(int vcpu_fd, struct kvm_interrupt *interrupt)
{
    pthread_mutex_lock(&s_cpu_mutex);

    #ifdef SE_KVM_DEBUG_IRQ
    printf("IRQ %d env->mflags=%x hflags=%x hflags2=%x ptr=%#x\n",
           interrupt->irq, env->mflags, env->hflags, env->hflags2, env->v_tpr);
    #endif

    assert(env->interrupt_request != CPU_INTERRUPT_HARD);
    env->interrupt_request = CPU_INTERRUPT_HARD;

    g_s2e_kvm_irq = interrupt->irq;

    cpu_exit(env);
    pthread_mutex_unlock(&s_cpu_mutex);

    return 0;
}
