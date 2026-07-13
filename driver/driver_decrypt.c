// driver_decrypt.c — full-disk decryption driver
// create() decodes the hex password (which is the disk key) back to
// binary, reads the header for sector layout, and decrypts all data
// to the file specified by --to.

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include "../include/windham_const.h"
#include "../libsrc/srclib.c"
#include "../libsrc/aes_xts_impl.c"

/* POSIX file I/O for raw block-device access (open/lseek/read/write).
   Under ISO C we fall back to stdio (fopen/fseeko/fread/fwrite) which
   cannot seek on block devices — fseeko failure triggers a read+discard
   fallback.  See decrypt_create() below.  */
#ifndef WINDHAM_ISOC
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

static const char *output_file_path;

void decrypt_set_output_file(const char *path) {
    output_file_path = path;
}

// hex char → nibble
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++)
        bin[i] = (uint8_t)((hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]));
}

// ── Driver interface ───────────────────────────────

static void decrypt_init(const char *driver_name) {
    (void)driver_name;
    is_device_mapper_available = true;
}

static int decrypt_try_create(const char *f, const char *e, const char *t) {
    (void)f; (void)e; (void)t;
    return EMOBJ_try_create_crypt_mapping_OK;
}

static int decrypt_create(
    const char *device, const char *name, const char *enc_type,
    const char *password, char uuid_str[37],
    size_t start_sector, size_t end_sector, size_t block_size,
    bool is_read_only, bool is_allow_discards,
    bool is_no_read_workqueue, bool is_no_write_workqueue)
{
    (void)name; (void)enc_type; (void)uuid_str;
    (void)is_read_only; (void)is_allow_discards;
    (void)is_no_read_workqueue; (void)is_no_write_workqueue;

    if (!output_file_path)
        print_error(_("decrypt driver requires --to=<output_file>"));

    // hex password is the disk key — decode it
    size_t disk_key_size = DEFAULT_DISK_KEY_SIZE_BYTES;
    uint8_t *disk_key = calloc(1, disk_key_size);
    if (!disk_key) { perror("malloc"); exit(1); }
    hex_to_bin(password, disk_key, disk_key_size);

    uint64_t total_512 = end_sector - start_sector;
    unsigned ratio = block_size / 512;
    uint64_t logical_sectors = total_512 / ratio;

#ifndef WINDHAM_ISOC
    int dev_fd = open(device, O_RDONLY);
    if (dev_fd < 0) { perror(device); exit(1); }

    int out_fd = creat(output_file_path, S_IRUSR | S_IWUSR);
    if (out_fd < 0) { perror(output_file_path); exit(1); }

    uint8_t *buf = malloc(block_size);
    if (!buf) { perror("malloc"); exit(1); }

    for (uint64_t ls = 0; ls < logical_sectors; ls++) {
        uint64_t f512 = start_sector + ls * ratio;
        off_t dev_off = (off_t)(f512 * 512);
        lseek(dev_fd, dev_off, SEEK_SET);
        if (read(dev_fd, buf, block_size) != (ssize_t)block_size)
            print_error(_("read error at sector %"PRIu64), f512);
        /* one XTS op per logical sector with dm-relative sector number as IV */
        aes_xts_decrypt_sectors(buf, 1, disk_key, (uint64_t)(ls * ratio), block_size);
        if (write(out_fd, buf, block_size) != (ssize_t)block_size)
            print_error(_("write error for output file"));
    }

    free(buf); free(disk_key);
    close(dev_fd); close(out_fd);
#else
    /* ISO C path — use stdio.  On block devices fseek/fseeko may fail,
       so we fread-and-discard the header area once, then read the data
       sectors sequentially without seeking. */
    FILE *dev_f = fopen(device, "rb");
    if (!dev_f) { perror(device); exit(1); }

    FILE *out_f = fopen(output_file_path, "wb");
    if (!out_f) { perror(output_file_path); exit(1); }

    uint8_t *buf = malloc(block_size);
    if (!buf) { perror("malloc"); exit(1); }

    /* Skip the header area by reading and discarding bytes.
       This works on block devices where fseek/fseeko may fail. */
    uint64_t header_bytes = start_sector * 512;
    while (header_bytes > 0) {
        size_t chunk = header_bytes > block_size ? block_size : (size_t)header_bytes;
        if (fread(buf, 1, chunk, dev_f) != chunk)
            print_error(_("error skipping header"));
        header_bytes -= chunk;
    }

    for (uint64_t ls = 0; ls < logical_sectors; ls++) {
        if (fread(buf, 1, block_size, dev_f) != block_size)
            print_error(_("read error at sector %"PRIu64), start_sector + ls * ratio);
        aes_xts_decrypt_sectors(buf, 1, disk_key, (uint64_t)(ls * ratio), block_size);
        if (fwrite(buf, 1, block_size, out_f) != block_size)
            print_error(_("write error for output file"));
    }

    free(buf); free(disk_key);
    fclose(dev_f); fclose(out_f);
#endif
    printf("decrypted %"PRIu64" sectors to %s\n", logical_sectors, output_file_path);
    return 0;
}

static bool decrypt_linear_map(const char *d, const char *n, uint64_t s, uint64_t sz, const char *u) {
    (void)d; (void)n; (void)s; (void)sz; (void)u; return false;
}
static void decrypt_map_partitions(const char *n, bool b) { (void)n; (void)b; }

Driver driver_decrypt = {
    .name = "decrypt", .init = decrypt_init, .try_create = decrypt_try_create,
    .create = decrypt_create, .remove = NULL,
    .remove_by_uuid = NULL, .linear_map = decrypt_linear_map,
    .map_partition_table = decrypt_map_partitions,
};
