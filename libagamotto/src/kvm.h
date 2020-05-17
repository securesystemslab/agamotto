// This file contains code derived from libs2e code

#ifndef LIBAGAMOTTO_KVM_H
#define LIBAGAMOTTO_KVM_H

#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>

#include <linux/kvm.h>

#define KVM_DEBUG_INTERFACE 1

extern struct kvm_run *g_kvm_vcpu_buffer;

typedef int (*open_t)(const char *pathname, int flags, mode_t mode);
typedef int (*close_t)(int fd);
typedef int (*ioctl_t)(int d, int request, ...);
typedef ssize_t (*write_t)(int fd, const void *buf, size_t count);
typedef int (*dup_t)(int fd);
typedef int (*poll_t)(struct pollfd *fds, nfds_t nfds, int timeout);
typedef int (*select_t)(int nfds, fd_set *readfds, fd_set *writefds,
                        fd_set *exceptfds, struct timeval *timeout);

typedef void (*exit_t)(int ret) __attribute__((__noreturn__));

typedef void *(*mmap_t)(void *addr, size_t len, int prot, int flags, int fd,
                        off_t offset);
typedef int (*madvise_t)(void *addr, size_t len, int advice);

extern ioctl_t g_original_ioctl;

int kvm_get_api_version(void);
int kvm_check_extension(int kvm_fd, int capability);
int kvm_create_vm(int kvm_fd);

int kvm_vm_ioctl_ioeventfd(int vm_fd, struct kvm_ioeventfd *event);
int kvm_vm_ioctl_register_coalesced_mmio(int vm_fd,
                                         struct kvm_coalesced_mmio_zone *zone);
int kvm_vm_ioctl_unregister_coalesced_mmio(
    int vm_fd, struct kvm_coalesced_mmio_zone *zone);
int kvm_vm_ioctl_assign_pci_device(int vm_fd, struct kvm_assigned_pci_dev *dev);

int handle_kvm_ioctl_trace(int fd, int request, uint64_t arg);
int handle_kvm_vm_ioctl_trace(int fd, int request, uint64_t arg);
int handle_kvm_vcpu_ioctl_trace(int fd, int request, uint64_t arg);

#endif
