#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <threads.h>

#include "../../include/windham_const.h"
#include "../../include/sha256.h"
#include "../../libsrc/srclib.c"


static bool is_rand_pool_init = false;
static uint8_t rand_pool[HASHLEN];
#ifndef __STDC_NO_THREADS__
mtx_t mutex_generate_entropy;
#endif


static int verify_unix_device(const char *path, int (*validator)(FILE*)) {
    FILE *dev = fopen(path, "rb+");
    if (!dev) return 1;

    int result = validator(dev);
    fclose(dev);
    return result;
}


static int validate_dev_null(FILE *dev) {
    char buf;
    if (fread(&buf, 1, 1, dev) != 0) {
        return 1;
    }

    const char test_data[] = "null_test";
    if (fwrite(test_data, 1, sizeof(test_data), dev) != sizeof(test_data)) {
        return 1;
    }
    fflush(dev);

    rewind(dev);
    if (fread(&buf, 1, 1, dev) != 0) {
        return 1;
    }

    return 0;
}


static int validate_dev_zero(FILE *dev) {
    unsigned char buf1[32];
    if (fread(buf1, 1, sizeof(buf1), dev) != sizeof(buf1)) {
        return 1;
    }

    if (memcmp(buf1, (unsigned char [sizeof(buf1)]){0}, sizeof(buf1)) != 0) {
        return 1;
    }

    rewind(dev);
    const char test_data[] = "zero_test";
    if (fwrite(test_data, 1, sizeof(test_data), dev) != sizeof(test_data)) {
        return 1;
    }
    fflush(dev);

    rewind(dev);
    if (fread(buf1, 1, sizeof(buf1), dev) != sizeof(buf1)) {
        return 1;
    }

    if (memcmp(buf1, (unsigned char [sizeof(buf1)]){0}, sizeof(buf1)) != 0) {
        return 1;
    }

    return 0;
}

void generate_entropy(uint8_t * buf, size_t len) {
#ifdef __STDC_NO_THREADS__
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

#ifndef __STDC_NO_THREADS__
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

#ifndef __STDC_NO_THREADS__
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


void fill_isoc_randpool() {
    struct timespec ts_start;
    struct timespec ts_end;
    uint_fast64_t ts_res;

    // get timespec resolution
#if (__STDC_VERSION__ >= 202311L)
    timespec_getres(&ts_start, TIME_UTC);
    ts_res = ts_start.tv_sec * 1000000000 + ts_start.tv_nsec;
#else
    timespec_get(&ts_start, TIME_UTC);
    while (1)
    {
        timespec_get(&ts_end, TIME_UTC);
        if (ts_end.tv_sec != ts_start.tv_sec && ts_end.tv_nsec != ts_start.tv_nsec)
        {
            ts_res = (ts_end.tv_sec - ts_start.tv_sec) * 1000000000 + (ts_end.tv_nsec - ts_start.tv_nsec);
            break;
        }
    }
#endif
    if (ts_res > 1000000) {
        print_warning(_("Low resolution timer (> 1ms), quality of the random seed will be compromised."));
    }

    timespec_get(&ts_start, TIME_UTC);
    printf("random source not available. input anything as entropy to facilitate random number generation");

    char input_entropy[128] = {0};
    if (fgets(input_entropy, sizeof(input_entropy), stdin) != input_entropy) {
        print_error(_("Entropy input error"));
    }
    if (strlen(input_entropy) < 10) {
        print_warning(_("entropy content too short"));
    }
    timespec_get(&ts_end, TIME_UTC);

    //update all items to sha256
    SHA256_CTX sha256_context;
    sha256_init(&sha256_context);
    sha256_update(&sha256_context, &ts_start, sizeof(struct timespec));
    sha256_update(&sha256_context, &input_entropy, strlen(input_entropy));
    sha256_update(&sha256_context, &ts_end, sizeof(struct timespec));
    sha256_final(&sha256_context, rand_pool);
    is_rand_pool_init = true;
}


void fill_unix_randpool(){
    FILE * fd = fopen("/dev/random", "rb");
    if (fread(rand_pool, sizeof(rand_pool), 1, fd) != 1) {
        print_warning(_("/dev/random read failed. Fallback to ISO C random schema."));
        fill_isoc_randpool();
    }
    fclose(fd);
    is_rand_pool_init = true;
}


void get_entropy_init(void) {
    if (verify_unix_device("/dev/null", validate_dev_null) &&
        verify_unix_device("/dev/zero", validate_dev_zero)) {
        fill_isoc_randpool();
    } else {
        fill_unix_randpool();
    }
#ifndef __STDC_NO_THREADS__
    mtx_init(&mutex_generate_entropy, mtx_plain);
#endif
}


#ifndef __STDC_NO_THREADS__
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
