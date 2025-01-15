/*
 * Note: This code is a fork and a derivation from the Argon2 reference implementation.
 *
 * Copyright 2024 2025
 * W. Wang (level-128)
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

/*For memory wiping*/
#ifdef _WIN32
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#endif
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#define VC_GE_2005(version) (version >= 1400)

/* for explicit_bzero() on glibc */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "thread.h"
#include "blake3.h"
#include "helper_func.h"

#ifdef GENKAT
#include "genkat.h"
#endif

#if defined(__clang__)
#if __has_attribute(optnone)
#define NOT_OPTIMIZED __attribute__((optnone))
#endif
#elif defined(__GNUC__)
#define GCC_VERSION                                                            \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40400
#define NOT_OPTIMIZED __attribute__((optimize("O0")))
#endif
#endif
#ifndef NOT_OPTIMIZED
#define NOT_OPTIMIZED
#endif

/***************Instance and Position constructors**********/
void init_block_value(block * b, uint8_t in) {
	memset(b->v, in, sizeof(b->v));
}

void copy_block(block * dst, const block * src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2B3_QWORDS_IN_BLOCK);
}

void xor_block(block * dst, const block * src) {
	int i;
	for (i = 0; i < ARGON2B3_QWORDS_IN_BLOCK; ++i) {
		dst->v[i] ^= src->v[i];
	}
}

static void load_block(block * dst, const void * input) {
	unsigned i;
	for (i = 0; i < ARGON2B3_QWORDS_IN_BLOCK; ++i) {
		dst->v[i] = load64((const uint8_t *) input + i * sizeof(dst->v[i]));
	}
}

static void store_block(void * output, const block * src) {
	unsigned i;
	for (i = 0; i < ARGON2B3_QWORDS_IN_BLOCK; ++i) {
		store64((uint8_t *) output + i * sizeof(src->v[i]), src->v[i]);
	}
}

#if defined(__OpenBSD__)
#define HAVE_EXPLICIT_BZERO 1
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#define HAVE_EXPLICIT_BZERO 1
#endif
#endif

void NOT_OPTIMIZED secure_wipe_memory(void * v, size_t n) {
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER) || defined(__MINGW32__)
	SecureZeroMemory(v, n);
#elif defined memset_s
	memset_s(v, n, 0, n);
#elif defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(v, n);
#else
	static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
	memset_sec(v, 0, n);
#endif
}

int FLAG_clear_internal_memory = ARGON2B3_CLEAR_INTERNAL_MEMORY;

void clear_internal_memory(void * v, size_t n) {
	if (FLAG_clear_internal_memory && v) {
		secure_wipe_memory(v, n);
	}
}

void finalize(const argon2B3_context * context, argon2_instance_t * instance) {
	if (context != NULL && instance != NULL) {
		block    blockhash;
		uint32_t l;

		copy_block(&blockhash, instance->memory + instance->lane_length - 1);

		/* XOR the last blocks */
		for (l = 1; l < instance->lanes; ++l) {
			uint32_t last_block_in_lane =
					l * instance->lane_length + (instance->lane_length - 1);
			xor_block(&blockhash, instance->memory + last_block_in_lane);
		}

		/* Hash the result */
		{
			uint8_t blockhash_bytes[ARGON2B3_BLOCK_SIZE];
			store_block(blockhash_bytes, &blockhash);
			blake3_hasher_long(context->out, context->outlen, blockhash_bytes,
			                   ARGON2B3_BLOCK_SIZE);
			/* clear blockhash and blockhash_bytes */
			clear_internal_memory(blockhash.v, ARGON2B3_BLOCK_SIZE);
			clear_internal_memory(blockhash_bytes, ARGON2B3_BLOCK_SIZE);
		}

#ifdef GENKAT
		print_tag(context->out, context->outlen);
#endif
	}
}

uint32_t index_alpha
(const argon2_instance_t * instance,
 const argon2_position_t * position,
 uint32_t                  pseudo_rand,
 int                       same_lane) {
	/*
	 * Pass 0:
	 *      This lane : all already finished segments plus already constructed
	 * blocks in this segment
	 *      Other lanes : all already finished segments
	 * Pass 1+:
	 *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
	 * blocks in this segment
	 *      Other lanes : (SYNC_POINTS - 1) last segments
	 */
	uint32_t reference_area_size;
	uint64_t relative_position;
	uint32_t start_position, absolute_position;

	if (0 == position->pass) {
		/* First pass */
		if (0 == position->slice) {
			/* First slice */
			reference_area_size =
					position->index - 1; /* all but the previous */
		} else {
			if (same_lane) {
				/* The same lane => add current segment */
				reference_area_size =
						position->slice * instance->segment_length +
						position->index - 1;
			} else {
				reference_area_size =
						position->slice * instance->segment_length +
						((position->index == 0) ? (-1) : 0);
			}
		}
	} else {
		/* Second pass */
		if (same_lane) {
			reference_area_size = instance->lane_length -
			                      instance->segment_length + position->index -
			                      1;
		} else {
			reference_area_size = instance->lane_length -
			                      instance->segment_length +
			                      ((position->index == 0) ? (-1) : 0);
		}
	}

	/* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
	 * relative position */
	relative_position = pseudo_rand;
	relative_position = relative_position * relative_position >> 32;
	relative_position = reference_area_size - 1 -
	                    (reference_area_size * relative_position >> 32);

	/* 1.2.5 Computing starting position */
	start_position = 0;

	if (0 != position->pass) {
		start_position = (position->slice == ARGON2B3_SYNC_POINTS - 1)
			                 ? 0
			                 : (position->slice + 1) * instance->segment_length;
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + relative_position) %
	                    instance->lane_length; /* absolute position */
	return absolute_position;
}

/* Single-threaded version for p=1 case */
static void fill_memory_blocks_st(argon2_instance_t * instance) {
	uint32_t r, s, l;

	for (r = 0; r < instance->passes; ++r) {
		for (s = 0; s < ARGON2B3_SYNC_POINTS; ++s) {
			for (l = 0; l < instance->lanes; ++l) {
				argon2_position_t position = {r, l, (uint8_t) s, 0};
				fill_segment(instance, position);
			}
		}
#ifdef GENKAT
		internal_kat(instance, r); /* Print all memory blocks */
#endif
	}
}

#if !defined(ARGON2B3_NO_THREADS)

#ifdef _WIN32
static unsigned __stdcall fill_segment_thr(void *thread_data)
#else

static void * fill_segment_thr(void * thread_data)
#endif
{
	argon2_thread_data * my_data = thread_data;
	fill_segment(my_data->instance_ptr, my_data->pos);
	argon2_thread_exit();
	return 0;
}

/* Multi-threaded version for p > 1 case */
static int fill_memory_blocks_mt(argon2_instance_t * instance) {
	uint32_t r, s;

	/* 1. Calculate the memory address for thread and thr_data */
	// the memory for argon2_thread_handle_t and argon2_thread_data is located after instance->memory.
	argon2_thread_handle_t * thread   = (argon2_thread_handle_t *) ((uintptr_t) instance->memory + instance->memory_blocks * sizeof(block));
	argon2_thread_data *     thr_data = (argon2_thread_data *) ((uintptr_t) thread + sizeof(argon2_thread_handle_t) * instance->lanes);

	memset(thread, 0, sizeof(argon2_thread_handle_t) * instance->lanes);
	memset(thr_data, 0, sizeof(argon2_thread_data) * instance->lanes);

	for (r = 0; r < instance->passes; ++r) {
		for (s = 0; s < ARGON2B3_SYNC_POINTS; ++s) {
			uint32_t l, ll;

			/* 2. Calling threads */
			for (l = 0; l < instance->lanes; ++l) {
				argon2_position_t position;

				/* 2.1 Join a thread if limit is exceeded */
				if (l >= instance->threads) {
					if (argon2_thread_join(thread[l - instance->threads])) {
						return ARGON2B3_THREAD_FAIL;
					}
				}

				/* 2.2 Create thread */
				position.pass            = r;
				position.lane            = l;
				position.slice           = (uint8_t) s;
				position.index           = 0;
				thr_data[l].instance_ptr =
						instance; /* preparing the thread input */
				memcpy(&(thr_data[l].pos), &position,
				       sizeof(argon2_position_t));
				if (argon2_thread_create(&thread[l], &fill_segment_thr,
				                         (void *) &thr_data[l])) {
					/* Wait for already running threads */
					for (ll = 0; ll < l; ++ll) {
						argon2_thread_join(thread[ll]);
					}
					return ARGON2B3_THREAD_FAIL;
				}

				/* fill_segment(instance, position); */
				/*Non-thread equivalent of the lines above */
			}

			/* 3. Joining remaining threads */
			for (l = instance->lanes - instance->threads; l < instance->lanes;
			     ++l) {
				if (argon2_thread_join(thread[l])) {
					return ARGON2B3_THREAD_FAIL;
				}
			}
		}

#ifdef GENKAT
		internal_kat(instance, r); /* Print all memory blocks */
#endif
	}

	return ARGON2B3_OK;
}

#endif /* ARGON2B3_NO_THREADS */

int fill_memory_blocks(argon2_instance_t * instance) {
#if defined(ARGON2B3_NO_THREADS)
	fill_memory_blocks_st(instance);
	return ARGON2B3_OK;
#else
	if (instance->threads == 1) {
		fill_memory_blocks_st(instance);
		return ARGON2B3_OK;
	} else {
		return fill_memory_blocks_mt(instance);
	}
#endif
}


// rewrote by the Windham author: W. Wang (level-128)
// Change the first and second block in each lane from G(H0||0||i) or
//	G(H0||1||i) to G(0 || i || *56 bytes of 0* || H0) and G(1 || i || *56 bytes of 0* || H0)
void fill_first_blocks(uint8_t * blockhash, const argon2_instance_t * instance) {
	uint32_t l;
	uint8_t  blockhash_bytes[ARGON2B3_BLOCK_SIZE];

	for (l = 0; l < instance->lanes; ++l) {
		// first block
		store32(blockhash, 0);
		store32(blockhash + 4, l);
		blake3_hasher_long(blockhash_bytes, ARGON2B3_BLOCK_SIZE, blockhash,
		                   ARGON2B3_PREHASH_SEED_LENGTH);
		load_block(&instance->memory[l * instance->lane_length + 0],
		           blockhash_bytes);

		// second block
		store32(blockhash, 1);
		blake3_hasher_long(blockhash_bytes, ARGON2B3_BLOCK_SIZE, blockhash,
		                   ARGON2B3_PREHASH_SEED_LENGTH);
		load_block(&instance->memory[l * instance->lane_length + 1],
		           blockhash_bytes);
	}
	clear_internal_memory(blockhash_bytes, ARGON2B3_BLOCK_SIZE);
}


// rewrote by the Windham author: W Wang (level-128)
// Original initial_hash Algorithm:

//	 buffer ← parallelism ∥ tagLength ∥ memorySizeKB ∥ iterations ∥ version ∥ hashType
//	 ∥ Length(password)       ∥ Password
//	 ∥ Length(salt)           ∥ salt
//	 ∥ Length(key)            ∥ key
//	 ∥ Length(associatedData) ∥ associatedData
//			H0 ← Blake2b(buffer, 64) //default hash size of Blake2b is 64-bytes

// Modified:
//  memory_for_metadata ← parallelism ∥ tagLength ∥ memorySizeKB ∥ iterations ∥ version ∥ hashType
//	         ∥ Length(password) ∥ Length(salt) ∥ * 32 bytes of 0*
//
//	 Padding <- length(salt) + length(pwd) % BLAKE3_BLOCK_LEN
//  Padding <- 0 if Padding == 0, else (64 - Padding)
//
//  memory_for_salt_sec_ad = *`Padding` bytes of 0* ∥ salt ∥ associatedData ∥ key
//
//			H0 ← BLAKE3(memory_for_metadata ∥ memory_for_salt_sec_ad ∥ Password, 64)
void initial_hash(uint8_t blockhash[ARGON2B3_PREHASH_DIGEST_LENGTH], argon2B3_context * context, argon2B3_type type) {
	blake3_hasher BlakeHash;

	blake3_hasher_init(&BlakeHash);

	uint32_t memory_for_metadata[8 + 8]; // 10 elements and padding to 64 bytes, occupies one BLAKE3 block length

	// 1. metadata for the first blake3 block
	store32(&memory_for_metadata[0], context->lanes);
	store32(&memory_for_metadata[1], context->outlen);
	store32(&memory_for_metadata[2], context->m_cost);
	store32(&memory_for_metadata[3], context->t_cost);
	store32(&memory_for_metadata[4], context->version);
	store32(&memory_for_metadata[5], (uint32_t) type);
	store32(&memory_for_metadata[6], context->pwdlen);
	store32(&memory_for_metadata[7], context->saltlen);

	memset(&memory_for_metadata[8], 0, sizeof(uint32_t) * 8);

	blake3_hasher_update(&BlakeHash, memory_for_metadata, sizeof(memory_for_metadata));

	// 2. calculate padding for the second blake3 block
	size_t padding = (context->saltlen + context->pwdlen) % BLAKE3_BLOCK_LEN;
	padding        = padding == 0 ? 0 : BLAKE3_BLOCK_LEN - padding;

	uint8_t zero_arr[BLAKE3_BLOCK_LEN] = {0};

	// 3. update salt and pwd.
	blake3_hasher_update(&BlakeHash, zero_arr, padding);
	blake3_hasher_update(&BlakeHash, context->salt, context->saltlen);
	blake3_hasher_update(&BlakeHash, (const uint8_t *) context->pwd, context->pwdlen);

	if (context->flags & ARGON2B3_FLAG_CLEAR_PASSWORD) {
		secure_wipe_memory(context->pwd, context->pwdlen);
		context->pwdlen = 0;
	}

	blake3_hasher_finalize(&BlakeHash, blockhash, ARGON2B3_PREHASH_DIGEST_LENGTH);
}


// Changed initial H_0 algorithm
void initialize(argon2_instance_t * instance, argon2B3_context * context) {
	uint8_t blockhash[ARGON2B3_PREHASH_SEED_LENGTH];
	instance->context_ptr = context;

	/* 1. Initial hashing */
	/* Hashing all inputs */
	// the result stores from the 65th byte of the blockhash, the 1-64th byte
	// will be used in fill_first_blocks
	initial_hash(blockhash + 64, context, instance->type);

#ifdef GENKAT
	initial_kat(blockhash, context, instance->type);
#endif

	/* 2. Creating first blocks, we always have at least two blocks in a slice
	 */
	// set the first blockhash to 0 before hashing
	memset(blockhash, 0, ARGON2B3_PREHASH_DIGEST_LENGTH); // ARGON2B3_PREHASH_DIGEST_LENGTH = 64

	// fill_first_blocks has changed in Argon2B3
	fill_first_blocks(blockhash, instance);
	/* Clearing the hash */


	clear_internal_memory(blockhash, ARGON2B3_PREHASH_SEED_LENGTH);
}
