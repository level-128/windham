// Compile-only check: verify that <linux/loop.h> is available and provides
// the ioctl constants and structs needed for direct loop device management
// via ioctl (LOOP_SET_FD, LOOP_CLR_FD, LOOP_SET_STATUS64, LOOP_CTL_GET_FREE, etc.)
//
// This is a compile-time check only. Runtime availability depends on:
//   - Root privileges or CAP_SYS_ADMIN
//   - Kernel version
//   - Seccomp/capabilities configuration
// There is no runtime fallback from ioctl to losetup -- it is decided at build time.

#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <string.h>

int main() {
    // Verify ioctl constants exist
    int a = LOOP_SET_FD;
    int b = LOOP_CLR_FD;
    int c = LOOP_SET_STATUS64;
    int d = LOOP_GET_STATUS64;
    int e = LOOP_SET_BLOCK_SIZE;
    int f = LOOP_CTL_GET_FREE;

    // Verify structs exist
    struct loop_info64 info;

    // Verify struct fields
    info.lo_flags = LO_FLAGS_AUTOCLEAR;

    // Suppress unused warnings
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;

    return 0;
}
