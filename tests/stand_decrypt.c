/* stand_decrypt.c — standalone decryption using our XTS
 * Usage: stand_decrypt <file> <hex_key> <block_size> <count>
 * Reads <count>*<block_size> bytes from <file> at offset 0,
 * decrypts with XTS, IV=0, and prints first 32 decrypted bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define AES256 1
#include "include/aes.h"
#include "libsrc/aes_xts_impl.c"

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <file> <hex_key_128> <block_size>\n", argv[0]);
        return 1;
    }
    const char *file   = argv[1];
    const char *hex    = argv[2];
    int block_size     = atoi(argv[3]);

    // Decode hex key
    if (strlen(hex) != 128) { fprintf(stderr, "key must be 128 hex chars\n"); return 1; }
    uint8_t key[64];
    for (int i = 0; i < 64; i++)
        key[i] = (uint8_t)((hex_nibble(hex[i*2]) << 4) | hex_nibble(hex[i*2+1]));

    // Read block_size bytes from file
    int fd = open(file, O_RDONLY);
    if (fd < 0) { perror(file); return 1; }
    uint8_t *buf = malloc(block_size);
    if (!buf) { perror("malloc"); return 1; }
    if (read(fd, buf, block_size) != block_size) { perror("read"); return 1; }
    close(fd);

    // Decrypt with XTS (sector 0 relative IV)
    aes_xts_decrypt_sectors(buf, 1, key, 0, block_size);

    // Print result
    printf("DEC: ");
    for (int i = 0; i < 32; i++) printf("%02x", buf[i]);
    printf("\n");

    // Count non-zero bytes
    int nonzero = 0;
    for (int i = 0; i < block_size; i++)
        if (buf[i] != 0) nonzero++;
    printf("non-zero: %d/%d\n", nonzero, block_size);

    free(buf);
    return nonzero == 0 ? 0 : 1;
}
