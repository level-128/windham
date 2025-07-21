#include <errno.h>
#include "windham_const.h"

#ifdef __linux__
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

#else
#include <fcntl.h>
#include <unistd.h>
#include <threads.h>

static int urandom_fd = -1;
static once_flag urandom_init_flag = ONCE_FLAG_INIT;

static void init_urandom(void) {
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        perror("open /dev/urandom");
        windham_exit(1);
    }
}

void fill_secure_random_bits(uint8_t *address, const size_t size) {
    size_t total_read = 0;
    ssize_t n;

    call_once(&urandom_init_flag, init_urandom);

    while (total_read < size) {
        n = read(urandom_fd, address + total_read, size - total_read);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read /dev/urandom");
            windham_exit(1);
        }
        total_read += n;
    }
}
#endif