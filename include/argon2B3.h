/*
 * Argon2B3 reference source code package - reference C implementations
 *
 * Note: This code is a fork and a derivation from the Argon2 reference implementation.
 * Argon2B3 is mostly Argon2. The major difference is Argon2B3 uses BLAKE3 for
 * instead of BLAKE2, and the algorithm for initializing blocks has been significantly
 * modified; Argon2B3 has achieved better protection per unit time when:
 * 1. m_cost / threads is very small (less than 1MiB).
 * 2. large output hash length
 *
 * This is achieved by using a significantly modified initial block generation
 * algorithm.
 *
 * Argon2B3 should only be used on platforms where computing resources are extremely
 * limited (e.g. embedded platform with no MMU). Thus, Argon2B3 archived optional
 * zero-dynamic allocation by requiring the caller to call a function that
 * computes and returns the required memory size.
 *
 * Copyright 2024
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

#ifndef ARGON2B3_H
#define ARGON2B3_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Symbols visibility control */
#ifdef A2_VISCTL
#define ARGON2B3_PUBLIC __attribute__((visibility("default")))
#define ARGON2B3_LOCAL __attribute__ ((visibility ("hidden")))
#elif defined(_MSC_VER)
#define ARGON2B3_PUBLIC __declspec(dllexport)
#define ARGON2B3_LOCAL
#else
#define ARGON2B3_PUBLIC
#define ARGON2B3_LOCAL
#endif

/*
 * Argon2B3 input parameter restrictions
 */

/* Minimum and maximum number of lanes (degree of parallelism) */
#define ARGON2B3_MIN_LANES UINT32_C(1)
#define ARGON2B3_MAX_LANES UINT32_C(0xFFFFFF)

/* Minimum and maximum number of threads */
#define ARGON2B3_MIN_THREADS UINT32_C(1)
#define ARGON2B3_MAX_THREADS UINT32_C(64)

/* Number of synchronization points between lanes per pass */
#define ARGON2B3_SYNC_POINTS UINT32_C(4)

/* Minimum and maximum digest size in bytes */
#define ARGON2B3_MIN_OUTLEN UINT32_C(4)
#define ARGON2B3_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
#define ARGON2B3_MIN_MEMORY (2 * ARGON2B3_SYNC_POINTS) /* 2 blocks per slice */

#define ARGON2B3_MIN(a, b) ((a) < (b) ? (a) : (b))
/* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
#define ARGON2B3_MAX_MEMORY_BITS                                                 \
    ARGON2B3_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
#define ARGON2B3_MAX_MEMORY                                                      \
    ARGON2B3_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2B3_MAX_MEMORY_BITS)

/* Minimum and maximum number of passes */
#define ARGON2B3_MIN_TIME UINT32_C(1)
#define ARGON2B3_MAX_TIME UINT32_C(0xFFFFFFFF)

/* Minimum and maximum password length in bytes */
#define ARGON2B3_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2B3_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum salt length in bytes */
#define ARGON2B3_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2B3_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

/* Flags to determine which fields are securely wiped (default = no wipe). */
#define ARGON2B3_DEFAULT_FLAGS UINT32_C(0)
#ifndef ARGON2B3_CLEAR_INTERNAL_MEMORY
#define ARGON2B3_CLEAR_INTERNAL_MEMORY (UINT32_C(1))
#endif

#ifndef ARGON2B3_FLAG_CLEAR_PASSWORD
#define ARGON2B3_FLAG_CLEAR_PASSWORD (UINT32_C(0))
#endif
/* Global flag to determine if we are wiping internal memory buffers. This flag
 * is defined in core.c and defaults to 1 (wipe internal memory). */
extern int FLAG_clear_internal_memory;


/* Error codes */
typedef enum Argon2_ErrorCodes {
 ARGON2B3_OK = 0, ARGON2B3_OUTPUT_PTR_NULL = -1, ARGON2B3_OUTPUT_TOO_SHORT = -2, ARGON2B3_OUTPUT_TOO_LONG = -3, ARGON2B3_PWD_TOO_SHORT = -4,
 ARGON2B3_PWD_TOO_LONG = -5, ARGON2B3_SALT_TOO_SHORT = -6, ARGON2B3_SALT_TOO_LONG = -7, ARGON2B3_AD_TOO_SHORT = -8, ARGON2B3_AD_TOO_LONG = -9,
 ARGON2B3_SECRET_TOO_SHORT = -10, ARGON2B3_SECRET_TOO_LONG = -11, ARGON2B3_TIME_TOO_SMALL = -12, ARGON2B3_TIME_TOO_LARGE = -13, ARGON2B3_MEMORY_TOO_LITTLE = -14,
 ARGON2B3_MEMORY_TOO_MUCH = -15, ARGON2B3_LANES_TOO_FEW = -16, ARGON2B3_LANES_TOO_MANY = -17, ARGON2B3_PWD_PTR_MISMATCH = -18, /* NULL ptr with non-zero length */
 ARGON2B3_SALT_PTR_MISMATCH = -19, /* NULL ptr with non-zero length */
 ARGON2B3_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
 ARGON2B3_AD_PTR_MISMATCH = -21, /* NULL ptr with non-zero length */

 ARGON2B3_MEMORY_ALLOCATION_ERROR = -22, ARGON2B3_MEMORY_LOCK_ERROR = -23, ARGON2B3_INCORRECT_TYPE = -26, ARGON2B3_OUT_PTR_MISMATCH = -27, ARGON2B3_THREADS_TOO_FEW = -28,
 ARGON2B3_THREADS_TOO_MANY = -29, ARGON2B3_MISSING_ARGS = -30, ARGON2B3_THREAD_FAIL = -31,
} argon2_error_codes;


/* Argon2B3 external data structures */

/*
 *****
 * Context: structure to hold Argon2B3 inputs:
 *  output array and its length,
 *  password and its length,
 *  salt and its length,
 *  number of passes, amount of used memory (in KBytes, can be rounded up a bit)
 *  number of parallel threads that will be run.
 * All the parameters above affect the output hash value.
 * Additionally, two function pointers can be provided to allocate and
 * deallocate the memory (if NULL, memory will be allocated internally).
 * Also, three flags indicate whether to erase password, secret as soon as they
 * are pre-hashed (and thus not needed anymore), and the entire memory
 */
// Note: Secret and associate data are not implemented in original Argon2 code. Removed.
typedef struct Argon2B3_Context {
 uint8_t * out; /* output array */
 uint32_t  outlen; /* digest length */

 uint8_t * pwd; /* password array */
 uint32_t  pwdlen; /* password length */

 uint8_t * salt; /* salt array */
 uint32_t  saltlen; /* salt length */

 uint32_t t_cost; /* number of passes */
 uint32_t m_cost; /* amount of memory requested (KB) */
 uint32_t lanes; /* number of lanes */
 uint32_t threads; /* maximum number of threads */

 uint32_t version; /* version number */

 uint32_t flags; /* array of bool options */
} argon2B3_context;


/* Argon2B3 primitive type */
typedef enum Argon2B3_type { Argon2B3_d = 0, Argon2B3_i = 1, Argon2B3_id = 2 } argon2B3_type;


/* Version of the algorithm */
typedef enum Argon2_version { ARGON2B3_VERSION_10 = 0x10, ARGON2B3_VERSION_13 = 0x13, ARGON2B3_VERSION_1 = 0x100, ARGON2B3_VERSION_NUMBER = ARGON2B3_VERSION_1 } argon2_version;


/*
 * Function that performs memory-hard hashing with certain degree of parallelism
 * @param  context  Pointer to the Argon2B3 internal structure
 * @return Error code if smth is wrong, ARGON2B3_OK otherwise
 * @note argon2B3_context *context will not be checked.
 */
ARGON2B3_PUBLIC int argon2b3_ctx(void * ctx_memory, argon2B3_context * context, argon2B3_type type);

/**
 * Hashes a password with Argon2, producing a raw hash at @hash
 * @param t_cost Number of iterations
 * @param m_cost Sets memory usage to m_cost kibibytes
 * @param parallelism Number of threads and compute lanes
 * @param pwd Pointer to password
 * @param pwdlen Password size in bytes
 * @param salt Pointer to salt
 * @param saltlen Salt size in bytes
 * @param hash Buffer where to write the raw hash - updated by the function
 * @param hashlen Desired length of the hash in bytes
 * @pre   Different parallelism levels will give different results
 * @pre   Returns ARGON2B3_OK if successful
 */
ARGON2B3_PUBLIC int argon2b3_hash_alloced(const uint32_t t_cost,
                                          const uint32_t m_cost,
                                          const uint32_t parallelism, const void * pwd,
                                          const size_t   pwdlen, const void *      salt,
                                          const size_t   saltlen, void *           hash,
                                          const size_t   hashlen, argon2B3_type    type);

size_t argon2b3_get_ctx_memory_size(const uint32_t m_cost, const uint32_t parallelism);

#ifndef ARGON2B3_DISABLE_DYNAMIC_MEMORY
// Ensure that the memory will never be swapped to disk.
ARGON2B3_PUBLIC int argon2b3_hash_alloced_locked_mem(const uint32_t t_cost, const uint32_t    m_cost,
                                                     const uint32_t parallelism, const void * pwd,
                                                     const size_t   pwdlen, const void *      salt,
                                                     const size_t   saltlen, void *           hash,
                                                     const size_t   hashlen, argon2B3_type    type);


/* generic function underlying the above ones */
// ctx_memory is the memory which will be used for intermediate Argon2B3 block.
// Before calling this function, use argon2b3_get_ctx_memory_size to calculate the memory size
// for void * ctx_memory.
ARGON2B3_PUBLIC int argon2b3_hash(void *         ctx_memory, const uint32_t t_cost, const uint32_t m_cost,
                                  const uint32_t parallelism, const void *  pwd,
                                  const size_t   pwdlen, const void *       salt,
                                  const size_t   saltlen, void *            hash,
                                  const size_t   hashlen, argon2B3_type     type);
#endif

/**
 * Get the associated error message for given error code
 * @return  The error message associated with the given error code
 */
ARGON2B3_PUBLIC const char * argon2b3_error_message(int error_code);


#if defined(__cplusplus)
}
#endif

#endif
