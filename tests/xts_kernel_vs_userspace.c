/* xts_kernel_vs_userspace.c — random key, multi-sector XTS comparison
 * Also tests hex round-trip: binary → hex → binary should be identity.
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>

#include "include/aes.h"
#include "libsrc/aes_xts_impl.c"

#define TEST_SECTORS     2   /* logical sectors */
#define SECTOR_SIZE_BYTES 4096
#define RATIO             (SECTOR_SIZE_BYTES / 512)  /* 8 for 4096, 1 for 512 */

static int systemf(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    return system(buf);
}

/* identical to driver/driver_dispatch.c:convert_disk_key_to_hex_format */
static void bin_to_hex(const uint8_t *key, size_t len, char *out) {
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[(key[i] >> 4) & 0xF];
        out[i*2+1] = hex[key[i] & 0xF];
    }
    out[len*2] = '\0';
}

/* identical to driver/driver_decrypt.c:hex_to_bin */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
static void hex_to_bin(const char *hex, uint8_t *bin, size_t len) {
    for (size_t i = 0; i < len; i++)
        bin[i] = (uint8_t)((hex_nibble(hex[i*2]) << 4) | hex_nibble(hex[i*2+1]));
}

int main(void) {
    const char *file = "/tmp/xts_test_backing.img";
    const char *name = "xts-test";

    /* 1. Generate random 64-byte key */
    uint8_t key[64];
    if (getrandom(key, 64, 0) != 64) {
        for (int i = 0; i < 64; i++) key[i] = (uint8_t)(i * 7 + 13);
    }

    /* 2. Hex-encode for dm-crypt, then round-trip back to binary to verify */
    char hex[129];
    bin_to_hex(key, 64, hex);
    uint8_t key2[64];
    hex_to_bin(hex, key2, 64);

    int hex_ok = memcmp(key, key2, 64) == 0;
    printf("Hex round-trip: %s\n", hex_ok ? "OK" : "FAIL");
    if (!hex_ok) {
        for (int i = 0; i < 64; i++)
            if (key[i] != key2[i]) printf("  byte[%d]: %02x -> '%c%c' -> %02x\n",
                i, key[i], hex[i*2], hex[i*2+1], key2[i]);
        return 1;
    }

    /* 3. Create backing file + loop device */
    int fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror(file); return 1; }
    ftruncate(fd, 8 * 1024 * 1024); close(fd);

    FILE *fp = popen("losetup -f", "r");
    fprintf(stderr, "losetup -f OK\n");
    if (!fp) return 1;
    char loop[256];
    fgets(loop, sizeof(loop), fp); pclose(fp);
    loop[strcspn(loop, "\n")] = '\0';
    fprintf(stderr, "loop=%s\n", loop);
    if (systemf("losetup %s %s 2>/dev/null", loop, file) != 0) return 1;
    fprintf(stderr, "losetup attached\n");

    /* 4. Create dm-crypt with random key AND non-zero device offset */
    uint64_t dev_offset = 56;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "dmsetup create %s --table '0 %d crypt aes-xts-plain64 %s 0 %s %" PRIu64 " 1 sector_size:%d' 2>/dev/null",
        name, TEST_SECTORS * RATIO, hex, loop, dev_offset, SECTOR_SIZE_BYTES);
    fprintf(stderr, "cmd: %s\n", cmd);
    if (system(cmd) != 0) {
        fprintf(stderr, "dmsetup create FAILED\n");
        systemf("losetup -d %s", loop); unlink(file); return 1;
    }
    fprintf(stderr, "dmsetup OK, writing zeros...\n");
    system("udevadm settle 2>/dev/null");
    usleep(2000000);  /* 2 seconds for dm-crypt to settle */

    /* 5. Write zeros through dm-crypt (kernel encrypts) */
    char dm_path[256];
    snprintf(dm_path, sizeof(dm_path), "/dev/mapper/%s", name);
    fd = open(dm_path, O_RDWR);
    if (fd < 0) { perror(dm_path); goto out; }
    size_t total = TEST_SECTORS * SECTOR_SIZE_BYTES;
    uint8_t *zeros = calloc(1, total);
    write(fd, zeros, total); free(zeros); close(fd);

    /* 6. Remove dm-crypt, flush, read raw encrypted data */
    systemf("dmsetup remove %s 2>/dev/null", name);
    sync();
    fd = open(loop, O_RDONLY);
    if (lseek(fd, (off_t)(dev_offset * 512), SEEK_SET) < 0) { perror("lseek"); return 1; }
    uint8_t *kernel_ct = malloc(total);
    ssize_t n = read(fd, kernel_ct, total);
    if (n != (ssize_t)total) { fprintf(stderr, "Short read: %zd/%zu\n", n, total); }

    /* 7. Userspace XTS encrypt — test with raw 512-byte sector numbers */
    uint8_t *userspace_ct = calloc(1, total);
    uint8_t *userspace_ct_alt = calloc(1, total);
    /* Use start_sector=0 for first, start_sector=8 for second (raw 512-byte numbering) */
    aes_xts_encrypt_sectors(userspace_ct, 1, key, 0, SECTOR_SIZE_BYTES);

    /* 7b. Decrypt round-trip: decrypt kernel ciphertext with our XTS, verify all-zero */
    uint8_t *decrypted = malloc(total);
    memcpy(decrypted, kernel_ct, total);
    aes_xts_decrypt_sectors(decrypted, 1, key, 0, SECTOR_SIZE_BYTES);
    int nz = 0;
    for (size_t i = 0; i < (size_t)SECTOR_SIZE_BYTES; i++)
        if (decrypted[i] != 0) nz++;
    fprintf(stderr, "DECRYPT-ROUNDTRIP non-zero: %d/%d\n", nz, SECTOR_SIZE_BYTES);
    free(decrypted);
    aes_xts_encrypt_sectors(userspace_ct + SECTOR_SIZE_BYTES, 1, key, 8, SECTOR_SIZE_BYTES);
    /* Also try original: start_sector=0 for 2 sectors (logical numbering) */
    aes_xts_encrypt_sectors(userspace_ct_alt, 2, key, 0, SECTOR_SIZE_BYTES);

    /* 8. Compare */
    printf("=== Method 1: start_sector=0,1 (logical) ===\n");
    for (int s = 0; s < TEST_SECTORS; s++) {
        int m = memcmp(kernel_ct + s * SECTOR_SIZE_BYTES,
                       userspace_ct_alt + s * SECTOR_SIZE_BYTES, SECTOR_SIZE_BYTES) == 0;
        printf(" Sector %d: %s\n", s, m ? "MATCH" : "MISMATCH");
    }
    printf("=== Method 2: start_sector=0,8 (raw 512-byte numbering) ===\n");
    for (int s = 0; s < TEST_SECTORS; s++) {
        int m = memcmp(kernel_ct + s * SECTOR_SIZE_BYTES,
                       userspace_ct + s * SECTOR_SIZE_BYTES, SECTOR_SIZE_BYTES) == 0;
        printf(" Sector %d: %s\n", s, m ? "MATCH" : "MISMATCH");
    }
    free(kernel_ct); free(userspace_ct); free(userspace_ct_alt);
out:
    systemf("dmsetup remove %s 2>/dev/null", name);
    systemf("losetup -d %s 2>/dev/null", loop);
    unlink(file);
    return 0;
}
