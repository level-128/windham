#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <threads.h>

#include "../include/argon2.h"

#define THREAD_COUNT 2


double timespec_diff_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1000000.0;
}


void argon2_compute(uint32_t m_cost, uint8_t *hash, struct timespec *start, struct timespec *end) {
    uint8_t pwd[HASHLEN] = {0};
    uint8_t salt[HASHLEN] = {1};

    timespec_get(start, TIME_UTC);
    int result = argon2id_hash_raw(
        1,             // t_cost
        m_cost,        // m_cost
        PARALLELISM,   // parallelism
        pwd,           // password
        HASHLEN,       // pwdlen
        salt,          // salt
        HASHLEN,       // saltlen
        hash,          // output hash
        HASHLEN,       // hashlen
        NULL,          // encoded
        NULL           // encodedlen
    );
    timespec_get(end, TIME_UTC);

    if (result == ARGON2_MEMORY_ALLOCATION_ERROR) {
        fprintf(stderr, "Memory allocation error for m_cost=%u\n", m_cost);
    }
}

#ifndef __STDC_NO_THREADS__
int argon2_thread(void *arg) {
    typedef struct {
        uint32_t m_cost;
        uint8_t hash[HASHLEN];
        struct timespec start, end;
    } thread_params;

    thread_params *params = (thread_params *)arg;
    uint8_t pwd[HASHLEN] = {0};
    uint8_t salt[HASHLEN] = {1};

    timespec_get(&params->start, TIME_UTC);
    int result = argon2id_hash_raw(
        1,
        params->m_cost,
        PARALLELISM,
        pwd,
        HASHLEN,
        salt,
        HASHLEN,
        params->hash,
        HASHLEN,
        NULL,
        NULL
    );
    timespec_get(&params->end, TIME_UTC);

    return result;
}
#endif


void benchmark() {
    printf("Starting Argon2id benchmark...\n");

    for (uint32_t mem_cost = 8; mem_cost <= 22; mem_cost < 20 ? mem_cost += 2 : mem_cost++) {
        uint32_t m_cost = (uint32_t)1 << mem_cost;
        printf("memory: %"PRIu32" KiB\n", m_cost);
        uint8_t hash1[HASHLEN];
        struct timespec start, end;

        argon2_compute(m_cost, hash1, &start, &end);
        double time1 = timespec_diff_ms(&start, &end);
        printf("Single-threaded time cost:  %.3f ms\n", time1);


#ifndef __STDC_NO_THREADS__
        printf("Multi-threaded mode:\n");
        struct timespec global_start, global_end;

        typedef struct {
            uint32_t m_cost;
            uint8_t hash[HASHLEN];
            struct timespec start, end;
        } thread_params;

        thread_params params[THREAD_COUNT] = {
            {.m_cost = m_cost},
            {.m_cost = m_cost}
        };

        thrd_t threads[THREAD_COUNT];

        timespec_get(&global_start, TIME_UTC);

        for (int i = 0; i < THREAD_COUNT; i++) {
            if (thrd_create(&threads[i], argon2_thread, &params[i]) != thrd_success) {
                fprintf(stderr, "Failed to create thread %d\n", i);
                return;
            }
        }

        for (int i = 0; i < THREAD_COUNT; i++) {
            int res;
            thrd_join(threads[i], &res);
            if (res == ARGON2_MEMORY_ALLOCATION_ERROR) {
                fprintf(stderr, "Memory error in thread %d\n", i);
                return;
            }
        }

        timespec_get(&global_end, TIME_UTC);

        double total_time = timespec_diff_ms(&global_start, &global_end);
        double thread1_time = timespec_diff_ms(&params[0].start, &params[0].end);
        double thread2_time = timespec_diff_ms(&params[1].start, &params[1].end);

        printf("Multi-thread Thread 1 compute time: %.3f ms\n", thread1_time);
        printf("Multi-thread Thread 2 compute time: %.3f ms\n", thread2_time);
        printf("Multi-thread Total time: %.3f ms\n", total_time);
        printf("Parallel efficiency: %.1f%%\n\n",
               time1 / total_time * 100);

#endif
    }
}
