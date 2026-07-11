/* xts_kernel_vs_userspace.c — compare dm-crypt XTS with userspace across multiple sectors
 * Compile: cc -std=c11 -I. -I library/tiny_AES_c xts_kernel_vs_userspace.c library/tiny_AES_c/aes.c -o /tmp/xts_cmp
 * Run:     pkexec /tmp/xts_cmp
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include "include/aes.h"
#include "libsrc/aes_xts_impl.c"

#define TEST_SECTORS 4

static int systemf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return system(buf);
}

int main(void) {
    const char *file = "/tmp/xts_test_backing.img";
    const char *name = "xts-test";
    char zero_hex[129];
    memset(zero_hex, '0', 128);
    zero_hex[128] = '\0';
    uint8_t key[64];
    memset(key, 0, 64);

    /* 1. Create backing file and loop device */
    int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror(file); return 1; }
    if (ftruncate(fd, 4 * 1024 * 1024) < 0) { perror("ftruncate"); close(fd); return 1; }
    close(fd);

    /* Find free loop */
    FILE *fp = popen("losetup -f", "r");
    if (!fp) { perror("losetup -f"); return 1; }
    char loop[256];
    if (!fgets(loop, sizeof(loop), fp)) { pclose(fp); return 1; }
    pclose(fp);
    loop[strcspn(loop, "\n")] = '\0';

    if (systemf("losetup %s %s 2>/dev/null", loop, file) != 0) {
        fprintf(stderr, "losetup %s %s failed\n", loop, file); return 1;
    }

    /* 2. Create dm-crypt with dmsetup (handles ioctl dance) */
    /* We use dmsetup if available, otherwise direct ioctl fallback */
    bool use_dmsetup = (system("which dmsetup >/dev/null 2>&1") == 0);
    if (use_dmsetup) {
        /* dmsetup: table format = start length crypt cipher key iv_offset device offset */
        if (systemf("dmsetup create %s --table '0 %d crypt aes-xts-plain64 %s 0 %s 0 1 sector_size:512' 2>/dev/null",
                    name, TEST_SECTORS, zero_hex, loop) != 0) {
            fprintf(stderr, "dmsetup create failed\n");
            systemf("losetup -d %s 2>/dev/null", loop);
            unlink(file); return 1;
        }
    } else {
        /* Direct ioctl — just try and if fails, report */
        fprintf(stderr, "dmsetup not found, trying direct ioctl...\n");
        int dm_fd = open("/dev/mapper/control", O_RDWR);
        if (dm_fd < 0) { perror("/dev/mapper/control"); goto cleanup; }
        /* ... complicated, skip for now */
        close(dm_fd);
        fprintf(stderr, "Direct ioctl not implemented in this test\n");
        goto cleanup;
    }

    /* 3. Write TEST_SECTORS * 512 zero bytes through dm-crypt */
    char dm_path[256];
    snprintf(dm_path, sizeof(dm_path), "/dev/mapper/%s", name);
    /* Wait for udev */
    system("udevadm settle 2>/dev/null");
    usleep(500000);

    fd = open(dm_path, O_RDWR);
    if (fd < 0) { perror(dm_path); systemf("dmsetup remove %s 2>/dev/null", name); goto cleanup; }

    size_t total = TEST_SECTORS * 512;
    uint8_t *zeros = calloc(1, total);
    if (write(fd, zeros, total) != (ssize_t)total) { perror("write zeros"); close(fd); goto out; }
    free(zeros);
    close(fd);

    /* 4. Remove dm-crypt (flush dirty pages) */
    if (use_dmsetup)
        systemf("dmsetup remove %s 2>/dev/null", name);

    /* 5. Read raw encrypted data from loop device */
    fd = open(loop, O_RDONLY);
    if (fd < 0) { perror(loop); goto cleanup; }

    uint8_t *kernel_ct = malloc(total);
    if (read(fd, kernel_ct, total) != (ssize_t)total) {
        perror("read raw"); close(fd); free(kernel_ct); goto cleanup;
    }
    close(fd);

    /* 6. Userspace XTS encrypt same zero plaintext */
    uint8_t *userspace_ct = calloc(1, total);
    aes_xts_encrypt_sectors(userspace_ct, TEST_SECTORS, key, 0, 512);

    /* 7. Compare each sector */
    int all_ok = 1;
    for (int s = 0; s < TEST_SECTORS; s++) {
        int match = memcmp(kernel_ct + s * 512, userspace_ct + s * 512, 512) == 0;
        printf("Sector %d: %s\n", s, match ? "MATCH" : "MISMATCH");
        if (!match) {
            all_ok = 0;
            printf("  Kernel   [0..31]: ");
            for (int i = 0; i < 32; i++) printf("%02x", kernel_ct[s*512 + i]);
            printf("\n  Userspace[0..31]: ");
            for (int i = 0; i < 32; i++) printf("%02x", userspace_ct[s*512 + i]);
            printf("\n");
        }
    }
    printf("ALL MATCH: %s\n", all_ok ? "YES" : "NO");

    free(kernel_ct);
    free(userspace_ct);

out:
    if (use_dmsetup)
        systemf("dmsetup remove %s 2>/dev/null", name);
cleanup:
    systemf("losetup -d %s 2>/dev/null", loop);
    unlink(file);
    return all_ok ? 0 : 1;
}
