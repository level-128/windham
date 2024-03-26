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
#include <blake3.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>

#define _(x) x

uint8_t bench_result[][32]={
		{(uintptr_t) NULL}};


int benchmark() {
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
	
	int t_cost = 1;
	uint8_t thread_test[4] = {1, 2, 4, 8};
	
	memset(pwd_array, 0, inlen);
	memset(salt_array, 1, inlen);
	
	uint8_t blake3_test[inlen];
	blake3_hasher_long(blake3_test, inlen, pwd_array, inlen);
	printf(_("\nBlake 3 test:\n"));
	print_hex_array(inlen, blake3_test);
	
	bool is_comp_bench_result = true;
	for (int i = 0; i <= 6; i += 1) {
		for (uint32_t thread_test_i = 0; thread_test_i < sizeof(thread_test); thread_test_i++){
			uint_fast32_t m_cost = 1 << (16 + i);
			
			clock_t start_time, stop_time;
			start_time = clock();
			
			void * ctx_memory = malloc(argon2b3_get_ctx_memory_size(m_cost, thread_test[sizeof(thread_test) - 1]));
			if (ctx_memory == NULL){
				printf(_("\nCannot benchmark using %"PRIuFAST32" MiB: insufficient RAM.\n"), m_cost >> 10);
				exit(0);
			}
			int result = argon2b3_hash(ctx_memory, t_cost, m_cost, thread_test[thread_test_i], pwd_array, inlen,
			                           salt_array, inlen, out, outlen, Argon2B3_id);
			
			if (result == ARGON2B3_MEMORY_TOO_MUCH){
				printf(_("\nCannot benchmark using %"PRIuFAST32" MiB: Address space exhausted under sub 64-bit platform.\n"), m_cost >> 10);
			}
			if (is_comp_bench_result){
				if (bench_result[i * sizeof(thread_test) + thread_test_i][0]){
					assert(memcmp(bench_result[i * sizeof(thread_test) + thread_test_i], out, outlen) == 0);
				} else {
					is_comp_bench_result = false;
				}
			}
			
			stop_time = clock();
			
			printf(_("\nResult: %d iterations, Memory cost: %"PRIuFAST32" MiB,  threads: %"PRIu32", time cost: %2.4f seconds * thread, Result: \n"), t_cost,
			       m_cost >> 10, thread_test[thread_test_i], ((double) (stop_time - start_time)) / (CLOCKS_PER_SEC));
			
			print_hex_array(outlen, out);
			fflush(stdout);
		}
		
	}
	exit(0);
}

