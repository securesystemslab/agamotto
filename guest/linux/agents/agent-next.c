#include <agamotto.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	agamotto_kvm_hypercall2(HC_AGAMOTTO_DEBUG, HC_AGAMOTTO_DEBUG_NEXT);

	return 0;
}
