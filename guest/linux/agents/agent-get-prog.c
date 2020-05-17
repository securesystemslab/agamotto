#include <agamotto.h>

int main(int argc, char** argv)
{
	uint64_t ret = agamotto_kvm_hypercall(HC_AGAMOTTO_GET_PROG);

	printf("%lu\n", ret);

	return 0;
}
