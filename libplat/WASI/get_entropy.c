/*
 * WASI / Emscripten entropy.
 *
 * WASI (wasi-sdk):  __wasi_random_get  (kernel CSPRNG)
 * Emscripten:        ISOC SHA256 chain  (__wasi_random_get ABI differs)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "../../include/windham_const.h"


#ifdef __EMSCRIPTEN__

#include "../../include/sha256.h"

static bool g_pool_init = false;
static uint8_t g_pool[HASHLEN];

void fill_secure_random_bits(uint8_t *address, const size_t size) {
    size_t remaining = size;
    uint8_t *dst = address;

    if (!g_pool_init) {
        struct timespec ts;
        timespec_get(&ts, TIME_UTC);
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, &ts, sizeof(ts));
        sha256_final(&ctx, g_pool);
        g_pool_init = true;
    }

    while (remaining > 0) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, g_pool, HASHLEN);
        sha256_final(&ctx, g_pool);

        size_t take = remaining < HASHLEN ? remaining : HASHLEN;
        memcpy(dst, g_pool, take);
        dst += take;
        remaining -= take;
    }
}

#else

#include <wasi/api.h>

void fill_secure_random_bits(uint8_t *address, const size_t size) {
    (void)__wasi_random_get(address, size);
}

#endif
