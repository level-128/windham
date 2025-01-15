/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * Copyright 2023
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
#include <argon2B3.h>
#include <blake3.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <inttypes.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>

#ifndef _
#define _(x) x
#endif

uint8_t bench_result[5][32] = {
	{
		0x39,
		0xda,
		0x8a,
		0x50,
		0x94,
		0xb3,
		0x28,
		0xc2,
		0xcb,
		0x1d,
		0xd4,
		0xf3,
		0xfa,
		0x98,
		0x7b,
		0x43,
		0xa0,
		0x12,
		0xc5,
		0x43,
		0x45,
		0xf1,
		0x01,
		0x56,
		0x85,
		0x32,
		0x24,
		0xcb,
		0xaf,
		0xc2,
		0xfb,
		0xa9
	},

	{
		0x30,
		0x2f,
		0x78,
		0x98,
		0x1b,
		0x59,
		0x8b,
		0x31,
		0xfd,
		0xea,
		0xc7,
		0xd6,
		0xeb,
		0x1f,
		0x46,
		0x6c,
		0x14,
		0x90,
		0x4d,
		0xe2,
		0x33,
		0xb4,
		0xd9,
		0x63,
		0x12,
		0x6b,
		0x00,
		0xc5,
		0xb5,
		0x5b,
		0x97,
		0x02
	},

	{
		0x43,
		0x8a,
		0xc1,
		0x47,
		0xf5,
		0x39,
		0xdc,
		0xfa,
		0xff,
		0x3a,
		0xcc,
		0xcf,
		0xf8,
		0x5e,
		0x4c,
		0x56,
		0x9d,
		0x37,
		0x1c,
		0xb9,
		0x7d,
		0x1e,
		0x86,
		0x28,
		0x70,
		0x82,
		0xa1,
		0x71,
		0x96,
		0x50,
		0xbf,
		0x38
	},

	{
		0x09,
		0x30,
		0xad,
		0x5f,
		0xc9,
		0x13,
		0x86,
		0x6e,
		0x66,
		0x2a,
		0xae,
		0x3e,
		0xe7,
		0xf8,
		0xa8,
		0x25,
		0x08,
		0x8d,
		0xbd,
		0x29,
		0x61,
		0xed,
		0xcf,
		0xcb,
		0x5c,
		0xf9,
		0xe9,
		0xc5,
		0x6e,
		0xf1,
		0xca,
		0x15
	},
	{0}
};


int benchmark() {
	printf(_("Start Argon2B3id benchmark:\n"));

	const uint32_t inlen  = 32;
	const unsigned outlen = 32;
	unsigned char  out[32];
	unsigned char  pwd_array[32];
	unsigned char  salt_array[32];

	int     t_cost         = 1;
	uint8_t thread_test[4] = {1, 2, 4, 8};

	memset(pwd_array, 0, inlen);
	memset(salt_array, 1, inlen);

	uint8_t blake3_test[inlen];
	blake3_hasher_long(blake3_test, inlen, pwd_array, inlen);
	printf(_("\nBlake 3 test:\n"));
	print_hex_array(inlen, blake3_test);

	bool    is_comp_bench_result = true;
	uint8_t zero_array[outlen];
	memset(zero_array, 0, outlen);

	for (int i = 0; i <= 6; i += 1) {
		uint_fast32_t m_cost     = 1 << (16 + i);
		void *        ctx_memory = malloc(argon2b3_get_ctx_memory_size(m_cost, thread_test[sizeof(thread_test) - 1]));
		if (ctx_memory == NULL) {
			printf(_("\nCannot benchmark using %"PRIuFAST32" MiB: insufficient RAM.\n"), m_cost >> 10);
			exit(0);
		}

		for (uint32_t thread_test_i = 0; thread_test_i < sizeof(thread_test); thread_test_i++) {
			struct timeval start,   end;
			long           seconds, useconds;
			double         elapsed;

			gettimeofday(&start, NULL);
			int result = argon2b3_hash
					(ctx_memory, t_cost, m_cost, thread_test[thread_test_i], pwd_array, inlen,
					 salt_array, inlen, out, outlen, Argon2B3_id);
			gettimeofday(&end, NULL);

			if (result == ARGON2B3_MEMORY_TOO_MUCH) {
				print_error(_("\nCannot benchmark using %"PRIuFAST32" MiB: Address space exhausted under sub 64-bit platform.\n"),
				            m_cost >> 10);
			}
			if (is_comp_bench_result) {
				if (memcmp(zero_array, bench_result[i * sizeof(thread_test) + thread_test_i], outlen) != 0) {
					if (memcmp(bench_result[i * sizeof(thread_test) + thread_test_i], out, outlen) != 0) {
						print_error
						(_("Result not pass for %d iterations, Memory cost: %"PRIuFAST32" MiB, threads: %"PRIu32"."), t_cost,
						 m_cost >> 10, thread_test[thread_test_i]);
					}
				} else {
					is_comp_bench_result = false;
				}
			}
			seconds  = end.tv_sec - start.tv_sec;
			useconds = end.tv_usec - start.tv_usec;
			elapsed  = seconds + useconds / 1000000.0;

			printf
					(_("\nResult: %d iterations, Memory cost: %"PRIuFAST32" MiB, threads: %"PRIu32
					   ", time cost: %2.4f seconds, Result: \n"), t_cost,
					 m_cost >> 10, thread_test[thread_test_i], elapsed);

			print_hex_array(outlen, out);
			fflush(stdout);
		}
		free(ctx_memory);
	}
	exit(0);
}
