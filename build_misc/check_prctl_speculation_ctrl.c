//
// Created by level-128 on 4/4/24.
//
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <stdio.h>


int main() {
	int result = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE, 0, 0);
	if (result == 0) {
		result = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
	}
	if (result == -1) {
		return 1;
	}
	return 0;
}
