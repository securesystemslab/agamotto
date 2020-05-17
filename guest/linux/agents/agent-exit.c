#include <agamotto.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	uint64_t ret = 0;

	if (argc > 1) {
		ret = strtoul(argv[1], NULL, 16);
	}

	agamotto_kvm_hypercall2(HC_AGAMOTTO_END, ret);

	return 0;
}
