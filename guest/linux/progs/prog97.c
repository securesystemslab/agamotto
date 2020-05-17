// benchmark driver

#include <agamotto.h>
#include <stdbool.h>

enum {
	DEBUG_HC_BENCHMARK = 12,
};

static bool should_exit(void)
{
	return false;
}

int main()
{
	while (!should_exit()) {
		agamotto_kvm_hypercall3(HC_AGAMOTTO_DEBUG, DEBUG_HC_BENCHMARK, 0);
	}

	return 0;
}
