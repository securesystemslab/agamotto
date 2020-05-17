#include <inttypes.h>
#include <stdio.h>

#include "kvm.h"

static const int MAX_MEMORY_SLOTS = 32;

struct kvm_run *g_kvm_vcpu_buffer;

int kvm_get_api_version(void) {
    return KVM_API_VERSION; // 12 on Ubuntu 18.04
}

int kvm_check_extension(int kvm_fd, int capability) {
    return g_original_ioctl(kvm_fd, KVM_CHECK_EXTENSION, capability);

    switch (capability) {
    case KVM_CAP_NR_MEMSLOTS: {
        return MAX_MEMORY_SLOTS;
    } break;

    case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
    case KVM_CAP_MP_STATE:
    case KVM_CAP_EXT_CPUID:
    case KVM_CAP_SET_TSS_ADDR:
    case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
    case KVM_CAP_USER_MEMORY:
    case KVM_CAP_NR_VCPUS:
    case KVM_CAP_MAX_VCPUS:
        return 1;

    default:
#ifdef KVM_DEBUG_INTERFACE
        printf("Unsupported cap %x\n", capability);
#endif
        return -1;
    }
}

int kvm_vm_ioctl_ioeventfd(int vm_fd, struct kvm_ioeventfd *event) {
    int ret = -1;
    return ret;
}

int kvm_vm_ioctl_register_coalesced_mmio(int vm_fd,
                                         struct kvm_coalesced_mmio_zone *zone) {
    int ret = -1;
    return ret;
}

int kvm_vm_ioctl_unregister_coalesced_mmio(
    int vm_fd, struct kvm_coalesced_mmio_zone *zone) {
    int ret = -1;
    return ret;
}

int kvm_vm_ioctl_assign_pci_device(int vm_fd,
                                   struct kvm_assigned_pci_dev *dev) {
    int ret = -1;
    return ret;
}

int handle_kvm_ioctl_trace(int fd, int request, uint64_t arg) {
    int ret = -1;
    return ret;
}

int handle_kvm_vm_ioctl_trace(int fd, int request, uint64_t arg) {
    int ret = -1;
    return ret;
}

int handle_kvm_vcpu_ioctl_trace(int fd, int request, uint64_t arg) {
    int ret = -1;
    return ret;
}
