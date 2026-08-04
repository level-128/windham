#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
/* C11 threads for mutex-protected entropy pool and once_flag
   initialisation; single-thread fallback when unavailable.  */
#ifndef __STDC_NO_THREADS__
#ifndef WINDHAM_NO_ISOC_THREAD
#include <threads.h>
#endif
#endif

#include "../../include/windham_const.h"
#include "../../include/sha256.h"
#include "../../libsrc/srclib.c"

// threads.h might be available yet disabled by WINDHAM_NO_ISOC_THREAD
#if defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)
#define WINDHAM_NO_ENTROPY_THREADS
#endif


static bool is_rand_pool_init = false;
static uint8_t rand_pool[HASHLEN];
#ifndef WINDHAM_NO_ENTROPY_THREADS
mtx_t mutex_generate_entropy;
#endif


void generate_entropy(uint8_t * buf, size_t len) {
#ifdef WINDHAM_NO_ENTROPY_THREADS
    static uint8_t internal_buffer[HASHLEN];
    struct internal_state {
        uint64_t counter;
        uint8_t stat;
    };
    static struct internal_state x;
    static unsigned len_left_in_buf = 0;
    static uint64_t counter = 0;
    static uint64_t reseed_counter = 1;
#else
    static _Thread_local uint8_t internal_buffer[HASHLEN];
    struct internal_state {
        uint64_t counter;
        thrd_t thread_no;
        uint8_t stat;
    };
    static struct internal_state _Thread_local x;
    static _Thread_local unsigned len_left_in_buf = 0;
    static _Thread_local uint64_t counter = 0;
    static _Thread_local uint64_t reseed_counter = 1;
#endif

    while (1){
        if (len > len_left_in_buf) {
            memcpy(buf, &internal_buffer[HASHLEN - len_left_in_buf], len_left_in_buf);
            len -= len_left_in_buf;
            buf += len_left_in_buf;
            len_left_in_buf = HASHLEN;

#ifndef WINDHAM_NO_ENTROPY_THREADS
            uint8_t tmp_rand_pool[HASHLEN];
            mtx_lock(&mutex_generate_entropy); // protect rand_pool from race condition.
            memcpy(tmp_rand_pool, rand_pool, HASHLEN);
            mtx_unlock(&mutex_generate_entropy);
            x.thread_no = thrd_current();
#else
            uint8_t * tmp_rand_pool = rand_pool;
#endif

            SHA256_CTX sha256_context;

            x.counter = counter;
            x.stat = 0;
            sha256_init(&sha256_context);
            sha256_update(&sha256_context, tmp_rand_pool, sizeof(HASHLEN));
            sha256_update(&sha256_context, &x, sizeof(struct internal_state));
            if (reseed_counter % 32 == 0) {
                struct timespec time;
                timespec_get(&time, TIME_UTC);
                sha256_update(&sha256_context, &time, sizeof(struct timespec));
            }
            sha256_final(&sha256_context, tmp_rand_pool);

            x.stat = 1;
            sha256_init(&sha256_context);
            sha256_update(&sha256_context, tmp_rand_pool, sizeof(HASHLEN));
            sha256_update(&sha256_context, &x, sizeof(struct internal_state));
            sha256_final(&sha256_context, internal_buffer);

#ifndef WINDHAM_NO_ENTROPY_THREADS
            mtx_lock(&mutex_generate_entropy); // protect rand_pool from race condition.
            memcpy(rand_pool, tmp_rand_pool, HASHLEN);
            mtx_unlock(&mutex_generate_entropy);
#endif

            counter ++;
            reseed_counter ++;
        } else {
            memcpy(buf, &internal_buffer[HASHLEN - len_left_in_buf], len);
            len_left_in_buf -= len;
            return;
        }
    }
}


// Shared seed for INTERNAL and WEAK trust levels.
// Mixes the platform-initial entropy source with a fresh timestamp.
// When need_keyboard is true, additionally prompts the user for input.
static void fill_combined_randpool(bool need_keyboard) {
    struct timespec ts_now;

    timespec_get(&ts_now, TIME_UTC);

    char input_entropy[128] = {0};
    if (need_keyboard) {
        printf("random source not available. input anything as entropy to facilitate random number generation");
        if (fgets(input_entropy, sizeof(input_entropy), stdin) != input_entropy)
            print_error(_("Entropy input error"));
        if (strlen(input_entropy) < 10)
            print_warning(_("entropy content too short"));
    }

    struct timespec ts_after;
    timespec_get(&ts_after, TIME_UTC);

    SHA256_CTX sha256_context;
    sha256_init(&sha256_context);
    sha256_update(&sha256_context, &init_val->initial_internal_entropy_source,
                  sizeof(init_val->initial_internal_entropy_source));
    sha256_update(&sha256_context, &ts_now, sizeof(struct timespec));
    sha256_update(&sha256_context, &ts_after, sizeof(struct timespec));
    if (need_keyboard)
        sha256_update(&sha256_context, input_entropy, strlen(input_entropy));
    sha256_final(&sha256_context, rand_pool);
    is_rand_pool_init = true;
}


void fill_unix_randpool(){
    FILE * fd = fopen("/dev/random", "rb");
    if (fread(rand_pool, sizeof(rand_pool), 1, fd) != 1) {
        print_warning(_("/dev/random read failed. Fallback to ISO C random schema."));
        fill_combined_randpool(true);
    }
    fclose(fd);
    is_rand_pool_init = true;
}


void get_entropy_init(void) {
    switch (init_val->is_random_number_trustworthy) {
    case EMOBJ_RANDOM_NUMBER_SYSTEM:
        fill_unix_randpool();
        break;
    case EMOBJ_RANDOM_NUMBER_INTERNAL:
        fill_combined_randpool(false);
        break;
    default: // EMOBJ_RANDOM_NUMBER_WEAK
        fill_combined_randpool(true);
        break;
    }
#ifndef WINDHAM_NO_ENTROPY_THREADS
    mtx_init(&mutex_generate_entropy, mtx_plain);
#endif
}


#ifndef WINDHAM_NO_ENTROPY_THREADS
static once_flag flag = ONCE_FLAG_INIT;
void fill_secure_random_bits(uint8_t *address, const size_t size) {
    call_once(&flag, get_entropy_init);
    generate_entropy(address, size);
}
#else
static bool is_inited = false;
void fill_secure_random_bits(uint8_t *address, const size_t size) {
    if (is_inited == false) {
        get_entropy_init();
        is_inited = true;
    }
    generate_entropy(address, size);
}
#endif
