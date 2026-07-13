#include <errno.h>
#include "windham_const.h"
#include <sys/random.h>

void fill_secure_random_bits(uint8_t *address, const size_t size) {
    FILL_BY_GETRANDOM:
    ssize_t size_filled = getrandom(address, size, 0);
    if (size_filled != (long)size) {
        if (errno == EINTR) {
            goto FILL_BY_GETRANDOM;
        }
        perror("getrandom");
        windham_exit(1);
    }
}