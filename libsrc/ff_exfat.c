// ff_exfat.c -- Create an exFAT filesystem on an encrypted Windham partition
// Depends only on FatFs declarations + ff_diskio, not on any driver.
// FatFs symbols are provided by an earlier #include in the chain.
#ifndef INCL_FF_EXFAT
#define INCL_FF_EXFAT

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/windham_const.h"
#include "../library/FatFs/ff.h"
#include "../library/FatFs/diskio.h"

static int ff_ex_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void ff_ex_hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++)
        bin[i] = (uint8_t)((ff_ex_hex_nibble(hex[i * 2]) << 4) | ff_ex_hex_nibble(hex[i * 2 + 1]));
}

void ff_exfat_create(const char *device_path, const char *hex_key,
                     size_t block_size, size_t start_sector, size_t end_sector)
{
    size_t key_size = DEFAULT_DISK_KEY_SIZE_BYTES;
    uint8_t *disk_key = calloc(1, key_size);
    if (!disk_key) { perror("malloc"); exit(1); }
    ff_ex_hex_to_bin(hex_key, disk_key, key_size);

    void *dev_handle = device_open(device_path, true);
    if (!dev_handle) { perror(device_path); free(disk_key); exit(1); }

    size_t part_sectors = end_sector - start_sector;
    ff_diskio_init(dev_handle, disk_key, block_size, start_sector, part_sectors, 1);

    MKFS_PARM opt;
    memset(&opt, 0, sizeof(opt));
    opt.fmt = FM_EXFAT | FM_SFD;	/* super-floppy: no MBR, volume starts at sector 0 */

    BYTE work[4096];
    FRESULT fr = f_mkfs(u"0:", &opt, work, sizeof(work));
    if (fr != FR_OK) {
        char *tbl[] = {"FR_OK","FR_DISK_ERR","FR_INT_ERR","FR_NOT_READY",
            "FR_NO_FILE","FR_NO_PATH","FR_INVALID_NAME","FR_DENIED","FR_EXIST",
            "FR_INVALID_OBJECT","FR_WRITE_PROTECTED","FR_INVALID_DRIVE",
            "FR_NOT_ENABLED","FR_NO_FILESYSTEM","FR_MKFS_ABORTED","FR_TIMEOUT",
            "FR_LOCKED","FR_NOT_ENOUGH_CORE","FR_TOO_MANY_OPEN_FILES","FR_INVALID_PARAMETER"};
        const char *name = (fr <= FR_INVALID_PARAMETER) ? tbl[fr] : "???";
        print_error(_("exFAT creation failed: %s (%d)"), name, (int)fr);
    }

    free(disk_key);
    device_close(dev_handle);
}

#endif
