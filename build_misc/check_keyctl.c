//
// Created by level-128 on 4/17/24.
//
#include <linux/keyctl.h>     /* Definition of KEY* constants */
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>
#include <errno.h>


int main() {
	syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, 0, 0);
	if (errno == -ENOSYS || errno == ENOSYS) {
		return 1;
	}
	return 0;
}
