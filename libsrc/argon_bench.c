/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * Copyright 2023 2024 2025
 * W. Wang (level-128)
 * modified for Windham project
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


#include <stdio.h>
#include <stdlib.h>

#include <inttypes.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>

#include "../include/argon2.h"

#ifndef _
#define _(x) x
#endif

uint8_t bench_result[5][32] = {
   {0}
};


int benchmark() {
   //
   // printf(_("Start Argon2B3id benchmark:\n"));
   //
   // const uint32_t inlen  = 32;
   // const unsigned outlen = 32;
   // unsigned char  out[32];
   // unsigned char  pwd_array[32];
   // unsigned char  salt_array[32];
   //
   // int     t_cost         = 1;
   // uint8_t thread_test[4] = {1, 2, 4, 8};
   //
   // memset(pwd_array, 0, inlen);
   // memset(salt_array, 1, inlen);
   //
   // uint8_t blake3_test[inlen];
   // blake3_hasher_long(blake3_test, inlen, pwd_array, inlen);
   // printf(_("\nBlake 3 test:\n"));
   // print_hex_array(inlen, blake3_test);
   //
   // bool    is_comp_bench_result = true;
   // uint8_t zero_array[outlen];
   // memset(zero_array, 0, outlen);
   //
   // for (int i = 0; i <= 6; i += 1) {
   // 	uint_fast32_t m_cost     = 1 << (16 + i);
   // 	void *        ctx_memory = malloc(argon2b3_get_ctx_memory_size(m_cost, thread_test[sizeof(thread_test) - 1]));
   // 	if (ctx_memory == NULL) {
   // 		printf(_("\nCannot benchmark using %"PRIuFAST32" MiB: insufficient RAM.\n"), m_cost >> 10);
   // 		exit(0);
   // 	}
   //
   // 	for (uint32_t thread_test_i = 0; thread_test_i < sizeof(thread_test); thread_test_i++) {
   // 		struct timeval start,   end;
   // 		long           seconds, useconds;
   // 		double         elapsed;
   //
   // 		gettimeofday(&start, NULL);
   // 		int result = argon2b3_hash
   // 				(ctx_memory, t_cost, m_cost, thread_test[thread_test_i], pwd_array, inlen,
   // 				 salt_array, inlen, out, outlen, Argon2B3_id);
   // 		gettimeofday(&end, NULL);
   //
   // 		if (result == ARGON2B3_MEMORY_TOO_MUCH) {
   // 			print_error(_("\nCannot benchmark using %"PRIuFAST32" MiB: Address space exhausted under sub 64-bit platform.\n"),
   // 			            m_cost >> 10);
   // 		}
   // 		if (is_comp_bench_result) {
   // 			if (memcmp(zero_array, bench_result[i * sizeof(thread_test) + thread_test_i], outlen) != 0) {
   // 				if (memcmp(bench_result[i * sizeof(thread_test) + thread_test_i], out, outlen) != 0) {
   // 					print_error
   // 					(_("Result not pass for %d iterations, Memory cost: %"PRIuFAST32" MiB, threads: %"PRIu32"."), t_cost,
   // 					 m_cost >> 10, thread_test[thread_test_i]);
   // 				}
   // 			} else {
   // 				is_comp_bench_result = false;
   // 			}
   // 		}
   // 		seconds  = end.tv_sec - start.tv_sec;
   // 		useconds = end.tv_usec - start.tv_usec;
   // 		elapsed  = seconds + useconds / 1000000.0;
   //
   // 		printf
   // 				(_("\nResult: %d iterations, Memory cost: %"PRIuFAST32" MiB, threads: %"PRIu32
   // 				   ", time cost: %2.4f seconds, Result: \n"), t_cost,
   // 				 m_cost >> 10, thread_test[thread_test_i], elapsed);
   //
   // 		print_hex_array(outlen, out);
   // 		fflush(stdout);
   // 	}
   // 	free(ctx_memory);
   // }
   exit(0);
}
