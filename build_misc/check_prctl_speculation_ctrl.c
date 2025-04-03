//
// Created by level-128 on 4/4/24.
//
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <stdio.h>
#include <errno.h>


int main() {
	int result = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 0, 0);
	if (result == 0) {
		result = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_ENABLE, 0, 0);
	}
	if (result == -1) {
		if (errno == ENODEV) {
			return 2; // Not supported by CPU or kernel
		}
		return 1; // Not possible
	}
	return 0; // Okay
}
