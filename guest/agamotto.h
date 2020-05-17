#ifndef _GUEST_AGAMOTTO_H
#define _GUEST_AGAMOTTO_H

#ifdef __MINGW64__
#ifndef uint64_t
#define uint64_t UINT64
#endif
#ifndef int32_t
#define int32_t INT32
#endif
#ifndef uint8_t
#define uint8_t UINT8
#endif
#else
#include <stdint.h>
#endif

#include <stdio.h>

#define KVM_HC_AGAMOTTO 20

#define HC_AGAMOTTO_GET_PROG 0
#define HC_AGAMOTTO_END 1
#define HC_AGAMOTTO_DEBUG 10
#define HC_AGAMOTTO_NEXT 20
#define SYZKALLER_HC_ROOT_CHKPT 5
#define HC_AGAMOTTO_DEBUG_NEXT 13

static uint64_t agamotto_kvm_hypercall(uint64_t a0)
{
	uint64_t ret;
	uint64_t nr = KVM_HC_AGAMOTTO;

	asm("movq %0, %%rbx;"
	    :
	    : "r"(a0));
	asm("movq %0, %%rax;"
	    :
	    : "r"(nr));
#ifdef X86_64_AMD_FAMILY
	asm("vmmcall; movq %% rax,%0"
	    : "=r"(ret)
	    :);
#else
	asm("vmcall; movq %% rax,%0"
	    : "=r"(ret)
	    :);
#endif
	return ret;
}

static uint64_t agamotto_kvm_hypercall2(uint64_t a0, uint64_t a1)
{
	uint64_t ret;
	uint64_t nr = KVM_HC_AGAMOTTO;

	asm("movq %0, %%rcx;"
	    :
	    : "r"(a1));
	asm("movq %0, %%rbx;"
	    :
	    : "r"(a0));
	asm("movq %0, %%rax;"
	    :
	    : "r"(nr));
#ifdef X86_64_AMD_FAMILY
	asm("vmmcall; movq %% rax,%0"
	    : "=r"(ret)
	    :);
#else
	asm("vmcall; movq %% rax,%0"
	    : "=r"(ret)
	    :);
#endif
	return ret;
}

static uint64_t agamotto_kvm_hypercall3(uint64_t a0, uint64_t a1, uint64_t a2)
{
	uint64_t ret;
	uint64_t nr = KVM_HC_AGAMOTTO;

	asm("movq %0, %%rsi;"
	    :
	    : "r"(a2));
	asm("movq %0, %%rcx;"
	    :
	    : "r"(a1));
	asm("movq %0, %%rbx;"
	    :
	    : "r"(a0));
	asm("movq %0, %%rax;"
	    :
	    : "r"(nr));
#ifdef X86_64_AMD_FAMILY
	asm("vmmcall; movq %% rax,%0"
	    : "=r"(ret)
	    :);
#else
	asm("vmcall; movq %% rax,%0"
	    : "=r"(ret)
	    :);
#endif
	return ret;
}

static void agamotto_agent_exit_cb()
{
	// TODO
}

#endif // _GUEST_AGAMOTTO_H
