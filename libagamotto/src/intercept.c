// This file contains code derived from libs2e code

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#undef __REDIRECT_NTH
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <agamotto.h>

#include "fuzzer.h"
#include "kvm.h"

static open_t s_original_open;

int g_trace = 0;
int g_kvm_fd = -1;
int g_kvm_vm_fd = -1;
int g_kvm_vcpu_fd = -1;

int open64(const char *pathname, int flags, ...) {
    va_list list;
    va_start(list, flags);
    mode_t mode = va_arg(list, mode_t);
    va_end(list);

    if (strcmp(pathname, "/dev/kvm") == 0) {
        printf("periscope: Opening %s\n", pathname);
        int fd = s_original_open("/dev/kvm", flags, mode);
        if (fd < 0) {
            printf("Could not open /dev/kvm\n");
            exit(-1);
        }

        g_kvm_fd = fd;
        return fd;
    } else {
        return s_original_open(pathname, flags, mode);
    }
}

static close_t s_original_close;
int close64(int fd) {
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
ssize_t write(int fd, const void *buf, size_t count) {
#if 0
  if (fd == g_kvm_fd || fd == g_kvm_vm_fd) {
    printf("write %d count=%ld\n", fd, count);
    exit(-1);
  }
#endif
    return s_original_write(fd, buf, count);
}

static int handle_kvm_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    switch ((uint32_t)request) {
#if 1
    case KVM_GET_API_VERSION:
        return kvm_get_api_version();
    case KVM_CHECK_EXTENSION:
        ret = kvm_check_extension(fd, arg1);
        break;
    case KVM_CREATE_VM:
        ret = g_original_ioctl(fd, request, arg1);
        g_kvm_vm_fd = ret;
        periscope_post_qemu_init();
        break;
    case KVM_GET_VCPU_MMAP_SIZE:
    case KVM_GET_MSR_INDEX_LIST:
    case KVM_GET_SUPPORTED_CPUID:
#else
    case KVM_CREATE_VM: {
        int tmpfd = s2e_kvm_create_vm(fd);
        if (tmpfd < 0) {
            printf("Could not create vm fd (errno=%d %s)\n", errno,
                   strerror(errno));
            exit(-1);
        }
        g_kvm_vm_fd = tmpfd;
        ret = tmpfd;
    } break;

    case KVM_GET_VCPU_MMAP_SIZE: {
        ret = s2e_kvm_get_vcpu_mmap_size();
    } break;

    case KVM_GET_MSR_INDEX_LIST: {
        ret = s2e_kvm_get_msr_index_list(fd, (struct kvm_msr_list *)arg1);
    } break;

    case KVM_GET_SUPPORTED_CPUID: {
        ret = s2e_kvm_get_supported_cpuid(fd, (struct kvm_cpuid2 *)arg1);
    } break;
#endif

    default: {
#ifdef PERISCOPE_TRACE_KVM_IOCTL
        fprintf(stderr, "periscope: unknown KVM IOCTL %x\n", request);
#endif
        ret = g_original_ioctl(fd, request, arg1);
        break;
        // exit(-1);
    }
    }

    return ret;
}

static int handle_kvm_vm_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    switch ((uint32_t)request) {
#if 1
    case KVM_CHECK_EXTENSION:
        ret = kvm_check_extension(fd, arg1);
        if (ret < 0) {
            errno = 1;
        }
        break;
    case KVM_SET_TSS_ADDR:
    case KVM_CREATE_VCPU:
    case KVM_SET_USER_MEMORY_REGION:
    case KVM_SET_CLOCK:
    case KVM_GET_CLOCK:
    case KVM_ENABLE_CAP:
    case KVM_IRQ_LINE_STATUS:
        ret = g_original_ioctl(fd, request, arg1);
        break;
    case KVM_GET_DIRTY_LOG:
        // printf("KVM_GET_DIRTY_LOG\n");
        ret = g_original_ioctl(fd, request, arg1);
        break;
    case KVM_IOEVENTFD:
        // ret = kvm_vm_ioctl_ioeventfd(fd, (struct kvm_ioeventfd *) arg1);
        // break;
    case KVM_SET_IDENTITY_MAP_ADDR:
    case KVM_REGISTER_COALESCED_MMIO:
        // ret = kvm_vm_ioctl_register_coalesced_mmio(fd, (struct
        // kvm_coalesced_mmio_zone *) arg1); break;
    case KVM_UNREGISTER_COALESCED_MMIO:
        // ret = kvm_vm_ioctl_unregister_coalesced_mmio(fd, (struct
        // kvm_coalesced_mmio_zone *) arg1); break;
    case KVM_ASSIGN_PCI_DEVICE:
        // ret = kvm_vm_ioctl_assign_pci_device(fd, (struct kvm_assigned_pci_dev
        // *) arg1);
        ret = g_original_ioctl(fd, request, arg1);
        break;
#if 0
  case KVM_MEM_RW:
  case KVM_FORCE_EXIT:
  case KVM_MEM_REGISTER_FIXED_REGION:
  case KVM_DISK_RW:
  case KVM_DEV_SNAPSHOT:
  case KVM_SET_CLOCK_SCALE:
#endif
        break;
#else
    case KVM_SET_TSS_ADDR: {
        ret = s2e_kvm_vm_set_tss_addr(fd, arg1);
    } break;

    case KVM_CREATE_VCPU: {
        ret = s2e_kvm_vm_create_vcpu(fd);
    } break;

    case KVM_SET_USER_MEMORY_REGION: {
        ret = s2e_kvm_vm_set_user_memory_region(
            fd, (struct kvm_userspace_memory_region *)arg1);
    } break;

    case KVM_SET_CLOCK: {
        ret = s2e_kvm_vm_set_clock(fd, (struct kvm_clock_data *)arg1);
    } break;

    case KVM_GET_CLOCK: {
        ret = s2e_kvm_vm_get_clock(fd, (struct kvm_clock_data *)arg1);
    } break;

    case KVM_ENABLE_CAP: {
        ret = s2e_kvm_vm_enable_cap(fd, (struct kvm_enable_cap *)arg1);
    } break;

    case KVM_IOEVENTFD: {
        ret = s2e_kvm_vm_ioeventfd(fd, (struct kvm_ioeventfd *)arg1);
    } break;

    case KVM_SET_IDENTITY_MAP_ADDR: {
        ret = s2e_kvm_vm_set_identity_map_addr(fd, arg1);
    } break;

    case KVM_GET_DIRTY_LOG: {
        ret = s2e_kvm_vm_get_dirty_log(fd, (struct kvm_dirty_log *)arg1);
    } break;

    case KVM_MEM_RW: {
        ret = s2e_kvm_vm_mem_rw(fd, (struct kvm_mem_rw *)arg1);
    } break;

    case KVM_FORCE_EXIT: {
        s2e_kvm_request_exit();
        ret = 0;
    } break;

    case KVM_MEM_REGISTER_FIXED_REGION: {
        ret = s2e_kvm_vm_register_fixed_region(fd,
                                               (struct kvm_fixed_region *)arg1);
    } break;

    case KVM_DISK_RW: {
        ret = s2e_kvm_vm_disk_rw(fd, (struct kvm_disk_rw *)arg1);
    } break;

    case KVM_DEV_SNAPSHOT: {
        ret = s2e_kvm_vm_dev_snapshot(fd, (struct kvm_dev_snapshot *)arg1);
    } break;

    case KVM_SET_CLOCK_SCALE: {
        ret = s2e_kvm_set_clock_scale_ptr(fd, (unsigned *)arg1);
    } break;
#endif

    default: {
#ifdef PERISCOPE_TRACE_KVM_IOCTL
        fprintf(stderr, "periscope: unknown KVM VM IOCTL %x\n", request);
#endif
        ret = g_original_ioctl(fd, request, arg1);
        break;
        // exit(-1);
    }
    }

    return ret;
}

static int handle_kvm_vcpu_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;
    switch ((uint32_t)request) {
#if 1
    case KVM_GET_CLOCK:
    case KVM_SET_CPUID2:
    case KVM_SET_SIGNAL_MASK:
        /***********************************************/
        // When the symbolic execution engine needs to take a system snapshot,
        // it must rely on the KVM client to save the device state. That client
        // will typically also save/restore the CPU state. We don't want the
        // client to do that, so in order to not modify the client too much, we
        // ignore the calls to register setters when they are done in the
        // context of device state snapshotting.
    case KVM_SET_REGS:
    case KVM_SET_FPU:
    case KVM_SET_SREGS:
    case KVM_SET_MSRS:
    case KVM_SET_MP_STATE:
    case KVM_GET_REGS:
    case KVM_GET_FPU:
    case KVM_GET_SREGS:
    case KVM_GET_MSRS:
    case KVM_GET_MP_STATE:
    case KVM_RUN:
    case KVM_INTERRUPT:
    case KVM_NMI:
        break;
#else
    case KVM_GET_CLOCK: {
        ret = s2e_kvm_vcpu_get_clock(fd, (struct kvm_clock_data *)arg1);
    } break;

    case KVM_SET_CPUID2: {
        ret = s2e_kvm_vcpu_set_cpuid2(fd, (struct kvm_cpuid2 *)arg1);
    } break;

    case KVM_SET_SIGNAL_MASK: {
        ret = s2e_kvm_vcpu_set_signal_mask(fd, (struct kvm_signal_mask *)arg1);
    } break;

        /***********************************************/
        // When the symbolic execution engine needs to take a system snapshot,
        // it must rely on the KVM client to save the device state. That client
        // will typically also save/restore the CPU state. We don't want the
        // client to do that, so in order to not modify the client too much, we
        // ignore the calls to register setters when they are done in the
        // context of device state snapshotting.
    case KVM_SET_REGS: {
        if (g_handling_dev_state) {
            ret = 0;
        } else {
            ret = s2e_kvm_vcpu_set_regs(fd, (struct kvm_regs *)arg1);
        }
    } break;

    case KVM_SET_FPU: {
        if (g_handling_dev_state) {
            ret = 0;
        } else {
            ret = s2e_kvm_vcpu_set_fpu(fd, (struct kvm_fpu *)arg1);
        }
    } break;

    case KVM_SET_SREGS: {
        if (g_handling_dev_state) {
            ret = 0;
        } else {
            ret = s2e_kvm_vcpu_set_sregs(fd, (struct kvm_sregs *)arg1);
        }
    } break;

    case KVM_SET_MSRS: {
        if (g_handling_dev_state) {
            ret = ((struct kvm_msrs *)arg1)->nmsrs;
        } else {
            ret = s2e_kvm_vcpu_set_msrs(fd, (struct kvm_msrs *)arg1);
        }
    } break;

    case KVM_SET_MP_STATE: {
        if (g_handling_dev_state) {
            ret = 0;
        } else {
            ret = s2e_kvm_vcpu_set_mp_state(fd, (struct kvm_mp_state *)arg1);
        }
    } break;
        /***********************************************/
    case KVM_GET_REGS: {
        if (g_handling_dev_state) {
            // Poison the returned registers to make sure we don't use
            // it again by accident. We can't just fail the call because
            // the client needs it to save the cpu state (that we ignore).
            memset((void *)arg1, 0xff, sizeof(struct kvm_regs));
            ret = 0;
        } else {
            ret = s2e_kvm_vcpu_get_regs(fd, (struct kvm_regs *)arg1);
        }
    } break;

    case KVM_GET_FPU: {
        ret = s2e_kvm_vcpu_get_fpu(fd, (struct kvm_fpu *)arg1);
    } break;

    case KVM_GET_SREGS: {
        ret = s2e_kvm_vcpu_get_sregs(fd, (struct kvm_sregs *)arg1);
    } break;

    case KVM_GET_MSRS: {
        ret = s2e_kvm_vcpu_get_msrs(fd, (struct kvm_msrs *)arg1);
    } break;

    case KVM_GET_MP_STATE: {
        ret = s2e_kvm_vcpu_get_mp_state(fd, (struct kvm_mp_state *)arg1);
    } break;

        /***********************************************/
    case KVM_RUN: {
        return s2e_kvm_vcpu_run(fd);
    } break;

    case KVM_INTERRUPT: {
        ret = s2e_kvm_vcpu_interrupt(fd, (struct kvm_interrupt *)arg1);
    } break;

    case KVM_NMI: {
        ret = s2e_kvm_vcpu_nmi(fd);
    } break;
#endif
    default: {
#ifdef PERISCOPE_TRACE_KVM_IOCTL
        fprintf(stderr,
                "periscope: unknown KVM VCPU IOCTL vcpu %d request=%#x "
                "arg=%#" PRIx64 " ret=%#x\n",
                fd, request, arg1, ret);
#endif
        ret = g_original_ioctl(fd, request, arg1);
        break;
        // exit(-1);
    }
    }

    return ret;
}

ioctl_t g_original_ioctl;
int ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    if (g_trace) {
        if (fd == g_kvm_fd) {
            // printf("ioctl %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd,
            // request, arg1, ret);
            ret = handle_kvm_ioctl_trace(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            // printf("ioctl vm %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd,
            // request, arg1, ret);
            ret = handle_kvm_vm_ioctl_trace(fd, request, arg1);
        } else if (fd == g_kvm_vcpu_fd) {
            ret = handle_kvm_vcpu_ioctl_trace(fd, request, arg1);
        } else {
            // printf("ioctl on %d\n", fd);
            ret = g_original_ioctl(fd, request, arg1);
        }
    } else {
        if (fd == g_kvm_fd) {
            // printf("ioctl %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd,
            // request, arg1, ret);
            ret = handle_kvm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vm_fd) {
            // printf("ioctl vm %d request=%#x arg=%#"PRIx64" ret=%#x\n", fd,
            // request, arg1, ret);
            ret = handle_kvm_vm_ioctl(fd, request, arg1);
        } else if (fd == g_kvm_vcpu_fd) {
            ret = handle_kvm_vcpu_ioctl(fd, request, arg1);
        } else {
            // printf("ioctl on %d\n", fd);
            ret = g_original_ioctl(fd, request, arg1);
        }
    }

    return ret;
}

static poll_t s_original_poll;
int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    // TODO: do we actually have to request exit from here?
    return s_original_poll(fds, nfds, timeout);
}

static select_t s_original_select;
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
    int ret = s_original_select(nfds, readfds, writefds, exceptfds, timeout);
#if 0
  s2e_kvm_request_exit();
#endif
    return ret;
}

static exit_t s_original_exit;
void exit(int code) {
    printf("Exiting with code=%d...\n", code);
    s_original_exit(code);
#if 0
  s2e_kvm_request_process_exit(s_original_exit, code);
#endif
}

#undef mmap

static mmap_t s_original_mmap;
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    if (fd < 0 || (fd != g_kvm_vcpu_fd)) {
        return s_original_mmap(addr, len, prot, flags, fd, offset);
    }

#if 0
  int real_size = s2e_kvm_get_vcpu_mmap_size();
  assert(real_size == len);
#endif
    assert(g_kvm_vcpu_buffer);

    return g_kvm_vcpu_buffer;
}

static mmap_t s_original_mmap64;
void *mmap64(void *addr, size_t len, int prot, int flags, int fd,
             off_t offset) {
    if (fd < 0 || (fd != g_kvm_vcpu_fd)) {
        return s_original_mmap64(addr, len, prot, flags, fd, offset);
    }

#if 0
  int real_size = s2e_kvm_get_vcpu_mmap_size();
  assert(real_size == len);
#endif
    assert(g_kvm_vcpu_buffer);

    return g_kvm_vcpu_buffer;
}

static dup_t s_original_dup;
int dup(int fd) {
    if (fd == g_kvm_vcpu_fd) {
        // This should work most of the time, but may break if the client
        // assumes that the returned fd must be different.
        return g_kvm_vcpu_fd;
    }

    return s_original_dup(fd);
}

static madvise_t s_original_madvise;
int madvise(void *addr, size_t len, int advice) {
    if (advice & MADV_DONTFORK) {
        // We must fork all memory for multi-core more
        advice &= ~MADV_DONTFORK;
    }

    if (!advice) {
        return 0;
    }

    return s_original_madvise(addr, len, advice);
}

///
/// \brief check_kvm_switch verifies that KVM mode is enabled.
///
/// It's a common mistake to preload this library but forget the --enable-kvm
/// switch
///
/// \param argc command line arg count
/// \param argv command line arguments
/// \return true if kvm switch is found
///
static bool check_kvm_switch(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        if (strstr(argv[i], "-enable-kvm")) {
            return true;
        }
    }

    return false;
}

#define MAX_SOCKET_PATH_STRING_SIZE 256

char monitor_socket_file[MAX_SOCKET_PATH_STRING_SIZE] = {0};

#if 0
static void check_monitor_socket(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        if (strstr(argv[i], "-monitor") && (i + 1 < argc)) {
            char buf[MAX_SOCKET_PATH_STRING_SIZE];

            // TODO: more thorough length check
            strncpy(buf, argv[i + 1], sizeof(buf));

            char *tok = strtok(buf, ",");
            if (tok) {
                tok = strtok(buf, ":");
                if (tok) {
                    strncpy(monitor_socket_file, strtok(NULL, ""),
                            sizeof(monitor_socket_file));
                    break;
                }
            }
        }
    }
}
#endif

// ****************************
// Overriding __llibc_start_main
// ****************************

// The type of __libc_start_main
typedef int (*T_libc_start_main)(int *(main)(int, char **, char **), int argc,
                                 char **ubp_av, void (*init)(void),
                                 void (*fini)(void), void (*rtld_fini)(void),
                                 void(*stack_end));

int __libc_start_main(int *(main)(int, char **, char **), int argc,
                      char **ubp_av, void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end)
    __attribute__((noreturn));

int __libc_start_main(int *(main)(int, char **, char **), int argc,
                      char **ubp_av, void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {

    T_libc_start_main orig_libc_start_main =
        (T_libc_start_main)dlsym(RTLD_NEXT, "__libc_start_main");
    s_original_open = (open_t)dlsym(RTLD_NEXT, "open64");
    s_original_close = (close_t)dlsym(RTLD_NEXT, "close64");
    g_original_ioctl = (ioctl_t)dlsym(RTLD_NEXT, "ioctl");
    s_original_write = (write_t)dlsym(RTLD_NEXT, "write");
    s_original_select = (select_t)dlsym(RTLD_NEXT, "select");
    s_original_poll = (poll_t)dlsym(RTLD_NEXT, "poll");
    s_original_exit = (exit_t)dlsym(RTLD_NEXT, "exit");
    s_original_mmap = (mmap_t)dlsym(RTLD_NEXT, "mmap");
    s_original_mmap64 = (mmap_t)dlsym(RTLD_NEXT, "mmap64");
    s_original_madvise = (madvise_t)dlsym(RTLD_NEXT, "madvise");
    s_original_dup = (dup_t)dlsym(RTLD_NEXT, "dup");

    // Hack when we are called from gdb or through a shell command
    if (strstr(ubp_av[0], "bash")) {
        (*orig_libc_start_main)(main, argc, ubp_av, init, fini, rtld_fini,
                                stack_end);
        exit(-1);
    }

    // This library might spawn other processes. This will fail if we preload
    // this library for these processes, so we must remove this environment
    // variable.
    unsetenv("LD_PRELOAD");

    // When libperiscope is used with qemu, verify that enable-kvm switch has
    // been specified.
    if (strstr(ubp_av[0], "qemu") && !check_kvm_switch(argc, ubp_av)) {
        printf("Please use -enable-kvm switch before starting QEMU\n");
        exit(-1);
    }

    char **new_argv = ubp_av;

    int agent_id = -1;
    char *agent_str = getenv("__PERISCOPE_GUEST_AGENT_ID");
    if (agent_str) {
        sscanf(agent_str, "%d", &agent_id);
    } else {
        printf("periscope: agent id not given\n");
    }

    int fuzzer_id = -1;
    char *fuzzer_str = getenv("SYZ_FUZZER_INDEX");
    if (fuzzer_str) {
        sscanf(fuzzer_str, "%d", &fuzzer_id);
    } else {
        printf("periscope: fuzzer id not given\n");
    }

    /*
     * Syzkaller
     */
    char *syz_fuzzer_path = getenv("SYZ_FUZZER_PATH");
    char *syz_fuzzer_argv = getenv("SYZ_FUZZER_ARGV");
    char *syz_fuzzer_executor = getenv("SYZ_FUZZER_EXECUTOR");
    char *syz_fuzzer_index = getenv("SYZ_FUZZER_INDEX");
    if (syz_fuzzer_path && syz_fuzzer_argv && syz_fuzzer_executor &&
        syz_fuzzer_index) {
        int out_st_pipe, out_ctl_pipe, shm_id = -1;

        // TODO(dokyungs): check if
        // char *syz_fuzzer_debug = getenv("SYZ_FUZZER_DEBUG");
        char fifo_base[50], fifo_out[50];
        char fifo_in[50];
        sprintf(fifo_base, "/tmp/serial-err-vm%s", syz_fuzzer_index);
        sprintf(fifo_in, "%s.in", fifo_base);
        remove(fifo_in);
        mkfifo(fifo_in, 0666);
        sprintf(fifo_out, "%s.out", fifo_base);
        remove(fifo_out);
        mkfifo(fifo_out, 0666);

        periscope_init_syz_fuzzer(
            ubp_av, syz_fuzzer_path, syz_fuzzer_argv, syz_fuzzer_executor,
            syz_fuzzer_index, &out_st_pipe, &out_ctl_pipe, &shm_id, fifo_out);
        int old_argc = argc;
        int new_argc = argc;
        new_argc += 2; // fuzzer

        // stderr pipe
        new_argc += 6;

        new_argv = (char **)malloc(sizeof(char *) * new_argc);
        memcpy(new_argv, ubp_av, sizeof(char *) * old_argc);

        char *mgr_pipe = getenv("SYZ_MANAGER_PIPE");

        char *chkpt_pool_size = getenv("__PERISCOPE_CHKPT_POOL_SIZE");

        new_argv[argc++] = "-device";
        char fuzzer[200];
        sprintf(fuzzer,
                "fuzzer,uri=%s:%d,st_pipe=%d,ctl_pipe=%d,mgr_pipe=%s,shm_id=%d,"
                "chkpt_pool_size=%s,%s,fuzzer_id=%d",
                "syzkaller", agent_id, out_st_pipe, out_ctl_pipe, mgr_pipe,
                shm_id, chkpt_pool_size, "hostmem1=mb1", fuzzer_id);
        new_argv[argc++] = fuzzer;

        // TODO(dokyungs)
        new_argv[argc++] = "-device";
        new_argv[argc++] = "virtio-serial-pci,id=virtio-serial2,ioeventfd=off";
        new_argv[argc++] = "-chardev";
        char err_pipe[100];
        sprintf(err_pipe, "pipe,id=ch2,path=%s", fifo_base);
        new_argv[argc++] = err_pipe;
        new_argv[argc++] = "-device";
        new_argv[argc++] =
            "virtserialport,bus=virtio-serial2.0,chardev=ch2,name=serial2";

        for (int i = 0; i < new_argc; i++) {
            printf("%s ", new_argv[i]);
        }
        printf("\n");

        if (argc != new_argc) {
            printf("periscope: arg handling error\n");
            exit(1);
        }

        argc = new_argc;

        goto start_main;
    } else {
        // error: invalid arg
    }

    int out_st_pipe, out_ctl_pipe = -1;
    periscope_pre_qemu_init(&out_st_pipe, &out_ctl_pipe);

#if 0
    check_monitor_socket(argc, ubp_av);
#endif

#define QEMU_FUZZER_IO_CHANNEL
//#undef QEMU_FUZZER_IO_CHANNEL
#ifdef QEMU_FUZZER_IO_CHANNEL
    /*
     * AFL
     */
    int shm_id = -1;
    char *shm_str = getenv("__AFL_SHM_ID");
    if (shm_str) {
        sscanf(shm_str, "%d", &shm_id);
    }

    if (out_st_pipe > -1 && out_ctl_pipe > -1) {
        char *chkpt_pool_size = getenv("__PERISCOPE_CHKPT_POOL_SIZE");

        argc += 2;

        new_argv = (char **)malloc(sizeof(char *) * argc);
        memcpy(new_argv, ubp_av, sizeof(char *) * argc - 2);
        new_argv[argc - 2] = "-device";
        char fuzzer[200];
        sprintf(fuzzer,
                "fuzzer,uri=%s:%d,st_pipe=%d,ctl_pipe=%d,shm_id=%d,"
                "chkpt_pool_size=%s,fuzzer_id=%d",
                "afl", agent_id, out_st_pipe, out_ctl_pipe, shm_id,
                chkpt_pool_size, fuzzer_id);
        new_argv[argc - 1] = fuzzer;
    }
#endif

#if 0
  if (!init_ram_size(argc, ubp_av)) {
    exit(-1);
  }
#endif
start_main:

    (*orig_libc_start_main)(main, argc, new_argv, init, fini, rtld_fini,
                            stack_end);

    exit(1); // This is never reached
}
