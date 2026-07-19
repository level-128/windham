/*
 * WASI entropy — direct __wasi_random_get, no SHA256 chain, no /dev/random.
 */

#include <stdint.h>
#include <stddef.h>
#include <wasi/api.h>

#include "../../include/windham_const.h"


void fill_secure_random_bits(uint8_t *address, const size_t size) {
    (void)__wasi_random_get(address, size);
}
