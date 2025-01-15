/*
 * Note: This code is a fork and a derivation from the Argon2 reference implementation.
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


#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "argon2B3.h"
#include "core.h"

#include "blake3.h"
#if ((defined(__amd64__) || defined(__x86_64__)) && !defined(__Argon2_opt_disable__))
#include "blamka-round-opt.h"
#else
#include "blamka-round-ref.h"
#include "helper_func.h"
#endif


/*
 * Function fills a new memory block and optionally XORs the old block over the new one.
 * Memory must be initialized.
 * @param state Pointer to the just produced block. Content will be updated(!)
 * @param ref_block Pointer to the reference block
 * @param next_block Pointer to the block to be XORed over. May coincide with @ref_block
 * @param with_xor Whether to XOR into the new block (1) or just overwrite (0)
 * @pre all block pointers must be valid
 */
#if ((defined(__amd64__) || defined(__x86_64__)) && !defined(__Argon2_opt_disable__))
#if defined(__AVX512F__)
static void fill_block
(__m512i *     state,
 const block * ref_block,
 block *       next_block,
 int           with_xor) {
	__m512i      block_XY[ARGON2B3_512BIT_WORDS_IN_BLOCK];
	unsigned int i;

	if (with_xor) {
		for (i = 0; i < ARGON2B3_512BIT_WORDS_IN_BLOCK; i++) {
			state[i] = _mm512_xor_si512(
			                            state[i], _mm512_loadu_si512((const __m512i *) ref_block->v + i));
			block_XY[i] = _mm512_xor_si512(
			                               state[i], _mm512_loadu_si512((const __m512i *) next_block->v + i));
		}
	} else {
		for (i = 0; i < ARGON2B3_512BIT_WORDS_IN_BLOCK; i++) {
			block_XY[i] = state[i] = _mm512_xor_si512(
			                                          state[i], _mm512_loadu_si512((const __m512i *) ref_block->v + i));
		}
	}

	for (i = 0; i < 2; ++i) {
		BLAKE2_ROUND_1(
		               state[8 * i + 0], state[8 * i + 1], state[8 * i + 2], state[8 * i + 3],
		               state[8 * i + 4], state[8 * i + 5], state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 2; ++i) {
		BLAKE2_ROUND_2(
		               state[2 * 0 + i], state[2 * 1 + i], state[2 * 2 + i], state[2 * 3 + i],
		               state[2 * 4 + i], state[2 * 5 + i], state[2 * 6 + i], state[2 * 7 + i]);
	}

	for (i = 0; i < ARGON2B3_512BIT_WORDS_IN_BLOCK; i++) {
		state[i] = _mm512_xor_si512(state[i], block_XY[i]);
		_mm512_storeu_si512((__m512i *) next_block->v + i, state[i]);
	}
}
#elif defined(__AVX2__)
static void fill_block(__m256i *state, const block *ref_block,
                       block *next_block, int with_xor) {
    __m256i block_XY[ARGON2B3_HWORDS_IN_BLOCK];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2B3_HWORDS_IN_BLOCK; i++) {
            state[i] = _mm256_xor_si256(
                state[i], _mm256_loadu_si256((const __m256i *)ref_block->v + i));
            block_XY[i] = _mm256_xor_si256(
                state[i], _mm256_loadu_si256((const __m256i *)next_block->v + i));
        }
    } else {
        for (i = 0; i < ARGON2B3_HWORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm256_xor_si256(
                state[i], _mm256_loadu_si256((const __m256i *)ref_block->v + i));
        }
    }

    for (i = 0; i < 4; ++i) {
        BLAKE2_ROUND_1(state[8 * i + 0], state[8 * i + 4], state[8 * i + 1], state[8 * i + 5],
                       state[8 * i + 2], state[8 * i + 6], state[8 * i + 3], state[8 * i + 7]);
    }

    for (i = 0; i < 4; ++i) {
        BLAKE2_ROUND_2(state[ 0 + i], state[ 4 + i], state[ 8 + i], state[12 + i],
                       state[16 + i], state[20 + i], state[24 + i], state[28 + i]);
    }

    for (i = 0; i < ARGON2B3_HWORDS_IN_BLOCK; i++) {
        state[i] = _mm256_xor_si256(state[i], block_XY[i]);
        _mm256_storeu_si256((__m256i *)next_block->v + i, state[i]);
    }
}
#else
static void fill_block(__m128i *state, const block *ref_block,
                       block *  next_block, int     with_xor) {
   __m128i      block_XY[ARGON2B3_OWORDS_IN_BLOCK];
   unsigned int i;

   if (with_xor) {
      for (i = 0; i < ARGON2B3_OWORDS_IN_BLOCK; i ++) {
         state[i] = _mm_xor_si128
            (
               state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
         block_XY[i] = _mm_xor_si128
            (
               state[i], _mm_loadu_si128((const __m128i *) next_block->v + i));
      }
   }
   else {
      for (i = 0; i < ARGON2B3_OWORDS_IN_BLOCK; i ++) {
         block_XY[i] = state[i] = _mm_xor_si128
            (
               state[i], _mm_loadu_si128((const __m128i *) ref_block->v + i));
      }
   }

   for (i = 0; i < 8; ++i) {
      BLAKE2_ROUND
      (state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
       state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
       state[8 * i + 6], state[8 * i + 7]);
   }

   for (i = 0; i < 8; ++i) {
      BLAKE2_ROUND
      (state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
       state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
       state[8 * 6 + i], state[8 * 7 + i]);
   }

   for (i = 0; i < ARGON2B3_OWORDS_IN_BLOCK; i ++) {
      state[i] = _mm_xor_si128(state[i], block_XY[i]);
      _mm_storeu_si128((__m128i *) next_block->v + i, state[i]);
   }
}
#endif
#else
static void fill_block(const block *prev_block, const block *ref_block,
                       block *      next_block, int          with_xor) {
   block    blockR, block_tmp;
   unsigned i;

   copy_block(&blockR, ref_block);
   xor_block(&blockR, prev_block);
   copy_block(&block_tmp, &blockR);
   /* Now blockR = ref_block + prev_block and block_tmp = ref_block + prev_block */
   if (with_xor) {
      /* Saving the next block contents for XOR over: */
      xor_block(&block_tmp, next_block);
      /* Now blockR = ref_block + prev_block and
         block_tmp = ref_block + prev_block + next_block */
   }

   /* Apply Blake2 on columns of 64-bit words: (0,1,...,15) , then
      (16,17,..31)... finally (112,113,...127) */
   for (i = 0; i < 8; ++i) {
      BLAKE2_ROUND_NOMSG
      (
         blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
         blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
         blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
         blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
         blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
         blockR.v[16 * i + 15]);
   }

   /* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113), then
      (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */
   for (i = 0; i < 8; i ++) {
      BLAKE2_ROUND_NOMSG
      (
         blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
         blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
         blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
         blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
         blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
         blockR.v[2 * i + 113]);
   }

   copy_block(next_block, &block_tmp);
   xor_block(next_block, &blockR);
}
#endif


static void next_addresses(block * address_block, block * input_block) {
	/*Temporary zero-initialized blocks*/
#if ((defined(__amd64__) || defined(__x86_64__)) && !defined(__Argon2_opt_disable__))
#if defined(__AVX512F__)
	__m512i zero_block[ARGON2B3_512BIT_WORDS_IN_BLOCK];
	__m512i zero2_block[ARGON2B3_512BIT_WORDS_IN_BLOCK];
#elif defined(__AVX2__)
    __m256i zero_block[ARGON2B3_HWORDS_IN_BLOCK];
    __m256i zero2_block[ARGON2B3_HWORDS_IN_BLOCK];
#else
   __m128i zero_block[ARGON2B3_OWORDS_IN_BLOCK];
   __m128i zero2_block[ARGON2B3_OWORDS_IN_BLOCK];
#endif
#else
   uint8_t zero_block[ARGON2B3_BLOCK_SIZE];
   uint8_t zero2_block[ARGON2B3_BLOCK_SIZE];
#endif

	memset(zero_block, 0, sizeof(zero_block));
	memset(zero2_block, 0, sizeof(zero2_block));

	/*Increasing index counter*/
	input_block->v[6]++;

#if ((defined(__amd64__) || defined(__x86_64__)) && !defined(__Argon2_opt_disable__))
	/*First iteration of G*/
	fill_block(zero_block, input_block, address_block, 0);

	/*Second iteration of G*/
	fill_block(zero2_block, address_block, address_block, 0);
#else
	/*First iteration of G*/
	fill_block((const block *)zero_block, input_block, address_block, 0);

	/*Second iteration of G*/
	fill_block((const block *)zero2_block, address_block, address_block, 0);
#endif
}


void fill_segment
(const argon2_instance_t * instance,
 argon2_position_t         position) {
	block *  ref_block = NULL, * curr_block = NULL;
	block    address_block,      input_block;
	uint64_t pseudo_rand,        ref_index, ref_lane;
	uint32_t prev_offset,        curr_offset;
	uint32_t starting_index,     i;

	int data_independent_addressing;

	if (instance == NULL) {
		return;
	}

	data_independent_addressing =
			(instance->type == Argon2B3_i) ||
			(instance->type == Argon2B3_id && (position.pass == 0) &&
			 (position.slice < ARGON2B3_SYNC_POINTS / 2));

	if (data_independent_addressing) {
		init_block_value(&input_block, 0);

		input_block.v[0] = position.pass;
		input_block.v[1] = position.lane;
		input_block.v[2] = position.slice;
		input_block.v[3] = instance->memory_blocks;
		input_block.v[4] = instance->passes;
		input_block.v[5] = instance->type;
	}

	starting_index = 0;

	if ((0 == position.pass) && (0 == position.slice)) {
		starting_index = 2; /* we have already generated the first two blocks */

		/* Don't forget to generate the first block of addresses: */
		if (data_independent_addressing) {
			next_addresses(&address_block, &input_block);
		}
	}

	/* Offset of the current block */
	curr_offset = position.lane * instance->lane_length +
	              position.slice * instance->segment_length + starting_index;

	if (0 == curr_offset % instance->lane_length) {
		/* Last block in this lane */
		prev_offset = curr_offset + instance->lane_length - 1;
	} else {
		/* Previous block */
		prev_offset = curr_offset - 1;
	}
#if ((defined(__amd64__) || defined(__x86_64__)) && !defined(__Argon2_opt_disable__))
#if defined(__AVX512F__)
	__m512i state[ARGON2B3_512BIT_WORDS_IN_BLOCK];
#elif defined(__AVX2__)
	__m256i state[ARGON2B3_HWORDS_IN_BLOCK];
#else
   __m128i state[ARGON2B3_OWORDS_IN_BLOCK];
#endif
	memcpy(state, ((instance->memory + prev_offset)->v), ARGON2B3_BLOCK_SIZE);
#else
   #define state (instance->memory + prev_offset)
#endif


	for (i = starting_index; i < instance->segment_length;
	     ++i, ++curr_offset, ++prev_offset) {
		/*1.1 Rotating prev_offset if needed */
		if (curr_offset % instance->lane_length == 1) {
			prev_offset = curr_offset - 1;
		}

		/* 1.2 Computing the index of the reference block */
		/* 1.2.1 Taking pseudo-random value from the previous block */
		if (data_independent_addressing) {
			if (i % ARGON2B3_ADDRESSES_IN_BLOCK == 0) {
				next_addresses(&address_block, &input_block);
			}
			pseudo_rand = address_block.v[i % ARGON2B3_ADDRESSES_IN_BLOCK];
		} else {
			pseudo_rand = instance->memory[prev_offset].v[0];
		}

		/* 1.2.2 Computing the lane of the reference block */
		ref_lane = ((pseudo_rand >> 32)) % instance->lanes;

		if ((position.pass == 0) && (position.slice == 0)) {
			/* Can not reference other lanes yet */
			ref_lane = position.lane;
		}

		/* 1.2.3 Computing the number of possible reference block within the
		 * lane.
		 */
		position.index = i;
		ref_index      = index_alpha
				(instance, &position, pseudo_rand & 0xFFFFFFFF,
				 ref_lane == position.lane);

		/* 2 Creating a new block */
		ref_block =
				instance->memory + instance->lane_length * ref_lane + ref_index;
		curr_block = instance->memory + curr_offset;

		if (0 == position.pass) {
			fill_block(state, ref_block, curr_block, 0);
		} else {
			fill_block(state, ref_block, curr_block, 1);
		}
	}
}
