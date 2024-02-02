/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * Copyright 2023
 * Weizheng Wang (modified for windham & Argon2B3)
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */
#include <argon2B3.h>

#include "srclib.c"

#if defined(__amd64__) || defined(__x86_64__)
static uint64_t rdtsc(void) {
	uint64_t rax, rdx;
	__asm__ __volatile__("rdtsc" : "=a"(rax), "=d"(rdx) : :);
	return (rdx << 32) | rax;
}
#else
static uint64_t rdtsc(void){return 0;};
#endif

noreturn void benchmark() {
	printf(_("Start Argon2B3id benchmark:\n"));

#define BENCH_OUTLEN 32
#define BENCH_INLEN 32
	const uint32_t inlen = BENCH_INLEN;
	const unsigned outlen = BENCH_OUTLEN;
	unsigned char out[BENCH_OUTLEN];
	unsigned char pwd_array[BENCH_INLEN];
	unsigned char salt_array[BENCH_INLEN];
#undef BENCH_INLEN
#undef BENCH_OUTLEN
	
	uint32_t t_cost = 1;
	uint32_t m_cost;
	uint32_t thread_test[4] = {1, 2, 4, 8};
	
	memset(pwd_array, 0, inlen);
	memset(salt_array, 1, inlen);
	
	for (m_cost = (uint32_t) 1 << 16; m_cost <= (uint32_t) 1 << 22; m_cost *= 2) {
		unsigned i;
		for (i = 0; i < 4; ++i) {
			uint32_t thread_n = thread_test[i];
			
			clock_t start_time, stop_time;
			uint64_t start_cycles, stop_cycles;
			double cpb;
			double mcycles;
			
			start_time = clock();
			start_cycles = rdtsc();
			
			argon2id_hash_raw(t_cost, m_cost, thread_n, pwd_array, inlen,
									salt_array, inlen, out, outlen);
			
			stop_cycles = rdtsc();
			stop_time = clock();
			
			cpb = ((double) (stop_cycles - start_cycles) * thread_n) / (m_cost * 1024);
			mcycles = (double) (stop_cycles - start_cycles) / (1UL << 20);
			
			if (mcycles == 0){
				printf(_("\nResult: %d iterations, Memory cost: %d MiB, %d threads, time cost: %2.4f seconds, Result: \n"), t_cost,
				       m_cost >> 10, thread_n, ((double) (stop_time - start_time)) / (CLOCKS_PER_SEC));
			} else {
				printf(_("\nResult: %d iterations, Memory cost: %d MiB, %d threads, time cost: %2.4f seconds, %2.2f Cycles per byte, %2.2f "
				         "Mcycles. Result: \n"), t_cost,
				       m_cost >> 10, thread_n, ((double) (stop_time - start_time)) / (CLOCKS_PER_SEC), cpb, mcycles);
			}
			print_hex_array(outlen, out);
		}
	}
	exit(0);
}

