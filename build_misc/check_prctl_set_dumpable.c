//
// Created by level-128 on 4/4/24.
//
#include <sys/prctl.h>


int main() {
	if (prctl(PR_SET_DUMPABLE, 0) == -1) {
		return 1;
	}
	return 0;
}
