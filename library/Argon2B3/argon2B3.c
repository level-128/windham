/*
 * Argon2B3 reference source code package - reference C implementations
 *
 * Note: This code is a fork and a derivation from the Argon2 reference implementation.
 * Argon2B3 is mostly Argon2. The major difference is Argon2B3 uses BLAKE3 for initial
 * block H0, G_0 and G_1 generation and final hash output instead of BLAKE2.
 *
 * Argon2B3 has achieved better protection per unit time when:
 * 1. m_cost / threads is very small (less than 1MiB).
 * 2. large output hash length
 *
 * This is done by using a significantly modified initial block generation
 * algorithm that is much faster than the original Argon2.
 *
 * Argon2B3 can be used on platforms where computing resources are extremely
 * limited (e.g. embedded platform with no MMU). Thus, Argon2B3 archived optional
 * zero-dynamic allocation by requiring the caller to call a function that
 * computes and returns the required memory size, then the caller passes the
 * allocated memory to the hash function.
 */

/*
 *
 * Copyright 2024 2025
 * W. Wang (level-128)
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
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
#include <string.h>

#include "argon2B3.h"
#include "core.h"


int validate_inputs(const argon2B3_context * context) {
	if (NULL == context->out) {
		return ARGON2B3_OUTPUT_PTR_NULL;
	}

	/* Validate output length */
	if (ARGON2B3_MIN_OUTLEN > context->outlen) {
		return ARGON2B3_OUTPUT_TOO_SHORT;
	}

	if (ARGON2B3_MAX_OUTLEN < context->outlen) {
		return ARGON2B3_OUTPUT_TOO_LONG;
	}

	/* Validate password (required param) */
	if (NULL == context->pwd) {
		if (0 != context->pwdlen) {
			return ARGON2B3_PWD_PTR_MISMATCH;
		}
	}

	if (ARGON2B3_MIN_PWD_LENGTH > context->pwdlen) {
		return ARGON2B3_PWD_TOO_SHORT;
	}

	if (ARGON2B3_MAX_PWD_LENGTH < context->pwdlen) {
		return ARGON2B3_PWD_TOO_LONG;
	}

	/* Validate salt (required param) */
	if (NULL == context->salt) {
		if (0 != context->saltlen) {
			return ARGON2B3_SALT_PTR_MISMATCH;
		}
	}

	if (ARGON2B3_MIN_SALT_LENGTH > context->saltlen) {
		return ARGON2B3_SALT_TOO_SHORT;
	}

	if (ARGON2B3_MAX_SALT_LENGTH < context->saltlen) {
		return ARGON2B3_SALT_TOO_LONG;
	}

	/* Validate memory cost */
	if (ARGON2B3_MIN_MEMORY > context->m_cost) {
		return ARGON2B3_MEMORY_TOO_LITTLE;
	}

	if (ARGON2B3_MAX_MEMORY < context->m_cost) {
		return ARGON2B3_MEMORY_TOO_MUCH;
	}

	if (context->m_cost < 8 * context->lanes) {
		return ARGON2B3_MEMORY_TOO_LITTLE;
	}

	/* Validate time cost */
	if (ARGON2B3_MIN_TIME > context->t_cost) {
		return ARGON2B3_TIME_TOO_SMALL;
	}

	if (ARGON2B3_MAX_TIME < context->t_cost) {
		return ARGON2B3_TIME_TOO_LARGE;
	}

	/* Validate lanes */
	if (ARGON2B3_MIN_LANES > context->lanes) {
		return ARGON2B3_LANES_TOO_FEW;
	}

	if (ARGON2B3_MAX_LANES < context->lanes) {
		return ARGON2B3_LANES_TOO_MANY;
	}

	/* Validate threads */
	if (ARGON2B3_MIN_THREADS > context->threads) {
		return ARGON2B3_THREADS_TOO_FEW;
	}

	if (ARGON2B3_MAX_THREADS < context->threads) {
		return ARGON2B3_THREADS_TOO_MANY;
	}

	return ARGON2B3_OK;
}


const char * argon2b3_error_message(int error_code) {
	switch (error_code) {
		case ARGON2B3_OK: return "OK";
		case ARGON2B3_OUTPUT_PTR_NULL: return "Output pointer is NULL";
		case ARGON2B3_OUTPUT_TOO_SHORT: return "Output is too short";
		case ARGON2B3_OUTPUT_TOO_LONG: return "Output is too long";
		case ARGON2B3_PWD_TOO_SHORT: return "Password is too short";
		case ARGON2B3_PWD_TOO_LONG: return "Password is too long";
		case ARGON2B3_SALT_TOO_SHORT: return "Salt is too short";
		case ARGON2B3_SALT_TOO_LONG: return "Salt is too long";
		case ARGON2B3_AD_TOO_SHORT: return "Associated data is too short";
		case ARGON2B3_AD_TOO_LONG: return "Associated data is too long";
		case ARGON2B3_SECRET_TOO_SHORT: return "Secret is too short";
		case ARGON2B3_SECRET_TOO_LONG: return "Secret is too long";
		case ARGON2B3_TIME_TOO_SMALL: return "Time cost is too small";
		case ARGON2B3_TIME_TOO_LARGE: return "Time cost is too large";
		case ARGON2B3_MEMORY_TOO_LITTLE: return "Memory cost is too small";
		case ARGON2B3_MEMORY_TOO_MUCH: return "Memory cost is too large";
		case ARGON2B3_LANES_TOO_FEW: return "Too few lanes";
		case ARGON2B3_LANES_TOO_MANY: return "Too many lanes";
		case ARGON2B3_PWD_PTR_MISMATCH: return "Password pointer is NULL, but password length is not 0";
		case ARGON2B3_SALT_PTR_MISMATCH: return "Salt pointer is NULL, but salt length is not 0";
		case ARGON2B3_SECRET_PTR_MISMATCH: return "Secret pointer is NULL, but secret length is not 0";
		case ARGON2B3_AD_PTR_MISMATCH: return "Associated data pointer is NULL, but ad length is not 0";
		case ARGON2B3_MEMORY_ALLOCATION_ERROR: return "Memory allocation error";
		case ARGON2B3_MEMORY_LOCK_ERROR: return "Cannot lock memory";
		case ARGON2B3_INCORRECT_TYPE: return "There is no such version of Argon2B3";
		case ARGON2B3_OUT_PTR_MISMATCH: return "Output pointer mismatch";
		case ARGON2B3_THREADS_TOO_FEW: return "Not enough threads";
		case ARGON2B3_THREADS_TOO_MANY: return "Too many threads";
		case ARGON2B3_MISSING_ARGS: return "Missing arguments";
		case ARGON2B3_THREAD_FAIL: return "Threading failure";
		default: return "Unknown error code";
	}
}


int argon2b3_ctx(void * ctx_memory, argon2B3_context * context, argon2B3_type type) {
	/* 1. Validate all inputs */
	uint32_t          memory_blocks, segment_length;
	argon2_instance_t instance;
	memset(&instance, 255, sizeof(instance));

	if (Argon2B3_d != type && Argon2B3_i != type && Argon2B3_id != type) {
		return ARGON2B3_INCORRECT_TYPE;
	}

	/* 2. Align memory size */
	/* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
	memory_blocks = context->m_cost;

	if (memory_blocks < 2 * ARGON2B3_SYNC_POINTS * context->lanes) {
		memory_blocks = 2 * ARGON2B3_SYNC_POINTS * context->lanes;
	}

	segment_length = memory_blocks / (context->lanes * ARGON2B3_SYNC_POINTS);
	/* Ensure that all segments have equal length */
	memory_blocks = segment_length * (context->lanes * ARGON2B3_SYNC_POINTS);

	instance.version        = context->version;
	instance.memory         = NULL;
	instance.passes         = context->t_cost;
	instance.memory_blocks  = memory_blocks;
	instance.segment_length = segment_length;
	instance.lane_length    = segment_length * ARGON2B3_SYNC_POINTS;
	instance.lanes          = context->lanes;
	instance.threads        = context->threads;
	instance.type           = type;
	instance.memory         = ctx_memory;

	if (instance.threads > instance.lanes) {
		instance.threads = instance.lanes;
	}

	/* 3. Initialization: Hashing inputs, allocating memory, filling first
	 * blocks
	 */
	initialize(&instance, context);

	/* 4. Filling memory */
	const int result = fill_memory_blocks(&instance);

	if (ARGON2B3_OK != result) {
		return result;
	}
	/* 5. Finalization */
	finalize(context, &instance);

	return ARGON2B3_OK;
}


size_t argon2b3_get_ctx_memory_size(const uint32_t m_cost, const uint32_t parallelism) {
	/* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
	uint32_t memory_blocks = m_cost;

	if (memory_blocks < 2 * ARGON2B3_SYNC_POINTS * parallelism) {
		memory_blocks = 2 * ARGON2B3_SYNC_POINTS * parallelism;
	}

	uint32_t segment_length = memory_blocks / (parallelism * ARGON2B3_SYNC_POINTS);
	/* Ensure that all segments have equal length */
	memory_blocks = segment_length * (parallelism * ARGON2B3_SYNC_POINTS);
	size_t res    = memory_blocks * sizeof(block);

#if !defined(ARGON2B3_NO_THREADS)
	if (parallelism > 1) {
		res += parallelism * (sizeof(argon2_thread_handle_t) + sizeof(argon2_thread_data));
	}
#endif

	return res;
}


int argon2b3_hash
(void *         ctx_memory,
 const uint32_t t_cost,
 const uint32_t m_cost,
 const uint32_t parallelism,
 const void *   pwd,
 const size_t   pwdlen,
 const void *   salt,
 const size_t   saltlen,
 void *         hash,
 const size_t   hashlen,
 argon2B3_type  type) {
	argon2B3_context context;
	int              result;

	if (hashlen > ARGON2B3_MAX_OUTLEN) {
		return ARGON2B3_OUTPUT_TOO_LONG;
	}

	if (hashlen < ARGON2B3_MIN_OUTLEN) {
		return ARGON2B3_OUTPUT_TOO_SHORT;
	}

	memset(&context, 0, sizeof(context));

	context.out     = (uint8_t *) hash;
	context.outlen  = (uint32_t) hashlen;
	context.pwd     = CONST_CAST(uint8_t *) pwd;
	context.pwdlen  = (uint32_t) pwdlen;
	context.salt    = CONST_CAST(uint8_t *) salt;
	context.saltlen = (uint32_t) saltlen;
	context.t_cost  = t_cost;
	context.m_cost  = m_cost;
	context.lanes   = parallelism;
	context.threads = parallelism;
	context.flags   = ARGON2B3_DEFAULT_FLAGS;
	context.version = ARGON2B3_VERSION_NUMBER;

	validate_inputs(&context);

	result = argon2b3_ctx(ctx_memory, &context, type);

	if (result != ARGON2B3_OK) {
		clear_internal_memory(hash, hashlen);
		return result;
	}
	return ARGON2B3_OK;
}

#ifndef ARGON2B3_DISABLE_DYNAMIC_MEMORY

int argon2b3_hash_alloced
(const uint32_t t_cost,
 const uint32_t m_cost,
 const uint32_t parallelism,
 const void *   pwd,
 const size_t   pwdlen,
 const void *   salt,
 const size_t   saltlen,
 void *         hash,
 const size_t   hashlen,
 argon2B3_type  type) {
	void * ctx_memory = malloc(argon2b3_get_ctx_memory_size(m_cost, parallelism));
	if (ctx_memory == NULL) {
		return ARGON2B3_MEMORY_ALLOCATION_ERROR;
	}
	enum Argon2_ErrorCodes status = argon2b3_hash
			(ctx_memory, t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
			 hash, hashlen, type);
	free(ctx_memory);
	return status;
}


#ifdef _WIN32
#include <windows.h>

int argon2b3_hash_raw_locked_mem(const uint32_t t_cost, const uint32_t m_cost,
                                 const uint32_t parallelism, const void *pwd,
                                 const size_t pwdlen, const void *salt,
                                 const size_t saltlen, void *hash, const size_t hashlen, argon2B3_type type) {

	 size_t ctx_memory_size = argon2id_get_ctx_memory_size(m_cost, parallelism);
    void * ctx_memory = VirtualAlloc(NULL, ctx_memory_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (ctx_memory == NULL) {
        return ARGON2B3_MEMORY_ALLOCATION_ERROR;
    }

    if (!VirtualLock(ctx_memory, ctx_memory_size)) {
        VirtualFree(ctx_memory, 0, MEM_RELEASE);
        return ARGON2B3_MEMORY_LOCK_ERROR;
    }

	enum Argon2_ErrorCodes status = argon2_hash(ctx_memory, t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
	                                            hash, hashlen, type);

    VirtualUnlock(ctx_memory, ctx_memory_size);
    VirtualFree(ctx_memory, 0, MEM_RELEASE);
    return status;
}
#else
#include <sys/mman.h>
#ifdef MAP_NORESERVE
#include <errno.h>


int argon2b3_hash_alloced_locked_mem
(const uint32_t t_cost,
 const uint32_t m_cost,
 const uint32_t parallelism,
 const void *   pwd,
 const size_t   pwdlen,
 const void *   salt,
 const size_t   saltlen,
 void *         hash,
 const size_t   hashlen,
 argon2B3_type  type) {
	int    prot            = PROT_READ | PROT_WRITE;
	int    flags           = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
	size_t ctx_memory_size = argon2b3_get_ctx_memory_size(m_cost, parallelism);

	void * ctx_memory = mmap(NULL, ctx_memory_size, prot, flags, -1, 0);
	if (ctx_memory == MAP_FAILED) {
		if (errno == ENOMEM) {
			return ARGON2B3_MEMORY_ALLOCATION_ERROR;
		}
	}
	if (mlock(ctx_memory, ctx_memory_size) == -1) {
		if (errno == ENOMEM || errno == EPERM) {
			return ARGON2B3_MEMORY_LOCK_ERROR;
		}
		return ARGON2B3_MEMORY_ALLOCATION_ERROR;
	}

	enum Argon2_ErrorCodes status = argon2b3_hash
			(ctx_memory, t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
			 hash, hashlen, type);
	munmap(ctx_memory, ctx_memory_size);
	return status;
}
#else // #ifdef MAP_LOCKED
int argon2b3_hash_raw_locked_mem(const uint32_t t_cost, const uint32_t m_cost,
                                 const uint32_t parallelism, const void *pwd,
                                 const size_t pwdlen, const void *salt,
                                 const size_t saltlen, void *hash, const size_t hashlen, argon2B3_type type) {
   return ARGON2B3_MEMORY_LOCK_ERROR;
}
#endif // #ifdef MAP_LOCKED
#endif // #ifdef _WIN32

#endif // #ifndef ARGON2B3_DISABLE_DYNAMIC_MEMORY
