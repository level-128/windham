#ifndef INCL_ENCLIB
#define INCL_ENCLIB


#include <stdint.h>
#include <string.h>
#include <time.h>
#include <float.h>
/* C11 threads for parallel KDF key search; single-thread fallback
   at read_key_from_data_one_level_dispatch() when unavailable.  */
#ifndef __STDC_NO_THREADS__
#ifndef WINDHAM_NO_ISOC_THREAD
#include <threads.h>
#endif
#endif

#include "endian.c"
#include "../include/windham_const.h"
#include "../include/aes.h"
#include "../include/sha256.h"
#include "../libplat/get_entropy.c"
#include "libkdf.c"
#include "srclib.c"



extern inline bool is_header_suspended(const Data encrypted_header) {
   return memcmp(encrypted_header.hint.windham_partition_magic_area, suspend_hint_tag, sizeof(suspend_hint_tag)) == 0;
}


uint64_t generate_memory_based_on_hash_value(const uint8_t hash[HASHLEN],
   const uint8_t master_key_mask[KEY_SLOT_EXP_MAX], int level_minus_one) {
   uint64_t diff = kdf_mem_bounds[level_minus_one][1] - kdf_mem_bounds[level_minus_one][0] + 1;
   if (diff == 1) {
      return kdf_mem_bounds[level_minus_one][0];
   }

   union {
      uint8_t buf[HASHLEN];
      uint64_t result;
   } cast_union = {.result=0};

   xor_with_len(HASHLEN, hash, master_key_mask, cast_union.buf);
   sha256_digest_all(cast_union.buf, sizeof(cast_union.buf), cast_union.buf);

   cast_union.result = be64toh(cast_union.result);
   uint64_t bias = cast_union.result % diff;

   return kdf_mem_bounds[level_minus_one][0] + bias;
}


void set_master_key_check(Data * data, const uint8_t master_key[HASHLEN]) {
   uint8_t hash[HASHLEN];
   sha256_digest_all(data->master_key_mask, HASHLEN, hash);
   memcpy(data->master_key_check, hash, AES_BLOCKLEN);

   struct AES_ctx ctx;
   AES_init_ctx(&ctx, master_key);
   AES_ECB_encrypt(&ctx, data->master_key_check);
}


bool check_master_key_check(const Data data, const uint8_t master_key[HASHLEN]) {
   uint8_t data_master_key_check[AES_BLOCKLEN];

   static uint8_t cached_master_key_mask[HASHLEN] = {0};
   static uint8_t cached_hash[HASHLEN]            = {0};
   static bool    cache_valid                     = false;

   if (! cache_valid || memcmp(cached_master_key_mask, data.master_key_mask, HASHLEN) != 0) {
      sha256_digest_all(data.master_key_mask, HASHLEN, cached_hash);
      memcpy(cached_master_key_mask, data.master_key_mask, HASHLEN);
      cache_valid = true;
   }

   memcpy(data_master_key_check, data.master_key_check, AES_BLOCKLEN);

   struct AES_ctx ctx;
   AES_init_ctx(&ctx, master_key);
   AES_ECB_decrypt(&ctx, data_master_key_check);
   return memcmp(data_master_key_check, cached_hash, AES_BLOCKLEN) == 0;
}


int read_key_from_data_one_level_st(
   Data       data,
   uint8_t    inited_keys_cpy[2][HASHLEN],
   uint16_t   keypool_loc,
   bool       is_allow_nolock,
   int        i,
   uint8_t    ret_master_key[HASHLEN],
   unsigned * ret_key_zone) {
   for (int j = 0; j < 2; j ++) {
      uint64_t mem = generate_memory_based_on_hash_value(inited_keys_cpy[j], data.master_key_mask, i);
      int result = kdf_hash(
         1,
         mem,
         PARALLELISM,
         inited_keys_cpy[j],
         HASHLEN,
         get_slot_loc(data, j, keypool_loc)->hash_salt,
         cal_salt_size(i),
         ret_master_key,
         HASHLEN,
         is_allow_nolock);
      if (result == NMOBJ_Enclib_calc_okay) {
         memcpy(inited_keys_cpy[j], ret_master_key, HASHLEN);
         xor_with_len(HASHLEN, ret_master_key, get_slot_loc(data, j, keypool_loc)->key_mask, ret_master_key);
         if (check_master_key_check(data, ret_master_key)) {
            *ret_key_zone = j;
            return NMOBJ_Enclib_calc_done;
         }
      } else {
         return result;
      }
   }
   return NMOBJ_Enclib_calc_okay;
}


typedef struct {
   int       i;
   int       j;
   Data *    data;
   uint8_t * inited_keys_cpy;
   uint8_t * ret_master_key;
   uint16_t  keypool_loc;
   bool      is_allow_nolock;
} Read_key_from_data_one_level_mt_thread_function_args;


int read_key_from_data_one_level_mt_thread_function(void * arg) {
   uint8_t                                                tmp_master_key[HASHLEN];
   Read_key_from_data_one_level_mt_thread_function_args * args   = arg;

   uint64_t mem = generate_memory_based_on_hash_value(args->inited_keys_cpy, args->data->master_key_mask, args->i);

   int                                                    result = kdf_hash(
      1,
      mem,
      PARALLELISM,
      args->inited_keys_cpy,
      HASHLEN,
      get_slot_loc((*args->data), args->j, args->keypool_loc)->hash_salt,
      cal_salt_size(args->i),
      tmp_master_key,
      HASHLEN,
      args->is_allow_nolock);
   if (result == NMOBJ_Enclib_calc_okay) {
      memcpy(args->inited_keys_cpy, tmp_master_key, HASHLEN);
      xor_with_len(HASHLEN, tmp_master_key, get_slot_loc((*args->data), args->j, args->keypool_loc)->key_mask, tmp_master_key);
      if (check_master_key_check(*args->data, tmp_master_key)) {
         memcpy(args->ret_master_key, tmp_master_key, HASHLEN);
         result = NMOBJ_Enclib_calc_done;
      }
   }
   return result;
}


bool read_key_from_data_one_level_dispatch(
   Data       data,
   uint8_t    inited_keys_cpy[2][HASHLEN],
   uint16_t   keypool_loc,
   bool       is_allow_nolock,
   int        i,
   uint8_t    ret_master_key[HASHLEN],
   unsigned * ret_key_zone,
   int *      ret_result) {
#if defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)
   return read_key_from_data_one_level_st(
   data,
   inited_keys_cpy,
   keypool_loc,
   is_allow_nolock,
   i,
   ret_master_key,
   ret_key_zone);

#else
   static bool is_mt_mem_okay = true;

   if (! is_mt_mem_okay) {
      return read_key_from_data_one_level_st(
         data,
         inited_keys_cpy,
         keypool_loc,
         is_allow_nolock,
         i,
         ret_master_key,
         ret_key_zone);
   }

   Read_key_from_data_one_level_mt_thread_function_args args[2];
   for (int j = 0; j < 2; j ++) {
      args[j].data            = &data;
      args[j].i               = i;
      args[j].j               = j;
      args[j].inited_keys_cpy = inited_keys_cpy[j];
      args[j].keypool_loc     = keypool_loc;
      args[j].is_allow_nolock = is_allow_nolock;
      args[j].ret_master_key  = ret_master_key;
   }

   thrd_t thread;

   if (thrd_create(&thread, read_key_from_data_one_level_mt_thread_function, &args[1]) != thrd_success) {
      perror("thrd_create");
      windham_exit(1);
   }

   int return_val = read_key_from_data_one_level_mt_thread_function(&args[0]);

   int thread_return_val;
   if (thrd_join(thread, &thread_return_val) != thrd_success) {
      perror("thrd_join");
      windham_exit(1);
   }

   if (MEM_ERR(return_val) && MEM_ERR(thread_return_val)) {
      // no need to restart, because mem is not enough even for one single thread.
      // return NMOBJ_Enclib_alloc_failed_policy_nolock first.
      if (return_val == NMOBJ_Enclib_alloc_failed_policy_nolock || thread_return_val == NMOBJ_Enclib_alloc_failed_policy_nolock) {
         *ret_result = NMOBJ_Enclib_alloc_failed_policy_nolock;
         return false;
      }
   }

   if (MEM_ERR(return_val)) {
      is_mt_mem_okay = false;
      return_val     = read_key_from_data_one_level_mt_thread_function(&args[0]);
      if (MEM_ERR(return_val)) {
         *ret_result = return_val;
         return false;
      }
   }

   if (MEM_ERR(thread_return_val)) {
      is_mt_mem_okay    = false;
      thread_return_val = read_key_from_data_one_level_mt_thread_function(&args[1]);
      if (MEM_ERR(thread_return_val)) {
         *ret_result = thread_return_val;
         return false;
      }
   }

   if (return_val == NMOBJ_Enclib_calc_done) {
      *ret_key_zone = 0;
      return true;
   }
   if (thread_return_val == NMOBJ_Enclib_calc_done) {
      *ret_key_zone = 1;
      return true;
   }

   *ret_result = NMOBJ_Enclib_calc_okay;
   return false;
#endif
}


int read_key_from_data(
   Data          data,
   const uint8_t inited_key[HASHLEN],
   uint16_t      keypool_loc,
   double        target_time,
   size_t        target_mem,
   const uint8_t max_level,
   bool          is_allow_nolock,
   unsigned *    ret_key_zone,
   unsigned *    ret_level,
   uint8_t       ret_master_key[HASHLEN]) {

   uint8_t inited_keys_cpy[2][HASHLEN];
   memcpy(inited_keys_cpy[0], inited_key, HASHLEN);
   memcpy(inited_keys_cpy[1], inited_key, HASHLEN);

   struct timespec start, current;
   double          elapsed_time;
   timespec_get(&start, TIME_UTC);

   for (int i = 0; i < KEY_SLOT_EXP_MAX; i ++) {
      if (i == max_level) {
         *ret_level = i;
         return NMOBJ_Enclib_calc_failed_level_exceeded;
      }
      if (kdf_mem_bounds[i][1] >= target_mem) {
         *ret_level = i;
         return NMOBJ_Enclib_calc_failed_reached_max_mem;
      }

      timespec_get(&current, TIME_UTC);
      elapsed_time = (current.tv_sec - start.tv_sec) +
                     (current.tv_nsec - start.tv_nsec) / 1e9;
      if (elapsed_time > target_time * 2) {
         *ret_level = i;
         return NMOBJ_Enclib_calc_failed_no_time;
      }

      int result;
      if (read_key_from_data_one_level_dispatch(
             data,
             inited_keys_cpy,
             keypool_loc,
             is_allow_nolock,
             i,
             ret_master_key,
             ret_key_zone,
             &result) == true) {
         *ret_level = i + 1;
         return NMOBJ_Enclib_calc_okay;
      }
      if (result != NMOBJ_Enclib_calc_okay) {
         *ret_level = i;
         return result;
      }
   }
   // Unreachable
   WINDHAM_UNREACHABLE
}

int generate_key_slot_key_mask(
   Data          data,
   const uint8_t inited_key[HASHLEN],
   const uint8_t master_key[HASHLEN],
   double        target_time,
   size_t        target_mem,
   const uint8_t max_level,
   bool          is_allow_nolock,
   int *         ret_level,
   Key_slot *    ret_target_slot) {
   int return_val;


   uint8_t inited_key_cpy[HASHLEN];
   memcpy(inited_key_cpy, inited_key, HASHLEN);

   struct timespec start, current;
   double          elapsed_time = +0.0;

   timespec_get(&start, TIME_UTC);

   for (int i = 0; i < KEY_SLOT_EXP_MAX; i ++) {
      if (i == max_level) {
         *ret_level = i;
         return_val = NMOBJ_Enclib_gen_okay_level_reached;
         goto BREAK_LOOP;
      }
      if (kdf_mem_bounds[i][1] >= target_mem) {
         *ret_level = i;
         return_val = NMOBJ_Enclib_gen_okay_mem_reached;
         goto BREAK_LOOP;
      }
      if (target_time != DBL_MAX) {
         // if user sets target_mem or max_level, then not using default time constrains
         timespec_get(&current, TIME_UTC);
         elapsed_time = (current.tv_sec - start.tv_sec) +
                        (double) (current.tv_nsec - start.tv_nsec) / 1e9;

         // This number is to ensure that after each iteration, elapsed_time is close to target_time.
         // log10(5)
         if (elapsed_time > target_time * 0.6989700043360189) {
            *ret_level = i;
            return_val = NMOBJ_Enclib_gen_okay_time_reached;
            goto BREAK_LOOP;
         }
      }

      uint8_t hash_result[HASHLEN];

      uint64_t mem = generate_memory_based_on_hash_value(inited_key_cpy, data.master_key_mask, i);

      int     result = kdf_hash(
         1,
         mem,
         PARALLELISM,
         inited_key_cpy,
         HASHLEN,
         ret_target_slot->hash_salt,
         cal_salt_size(i),
         hash_result,
         HASHLEN,
         is_allow_nolock);
      memcpy(inited_key_cpy, hash_result, HASHLEN);
      if (result != NMOBJ_Enclib_calc_okay) { // error and return
         *ret_level = i;
         return result;
      }
   }
#ifdef __GNUC__
   __builtin_unreachable();
#endif

BREAK_LOOP:
   xor_with_len(HASHLEN, master_key, inited_key_cpy, ret_target_slot->key_mask);
   return return_val;
}


uint16_t get_keypool_location_candidate(const uint8_t master_key_mask[HASHLEN], const uint8_t inited_key[HASHLEN]) {
   union {
      uint64_t u64;
      uint8_t  hash[HASHLEN];
   } val;
   val.u64 = 0;
   SHA256_CTX sha_256_ctx;
   sha256_init(&sha_256_ctx);
   sha256_update(&sha_256_ctx, master_key_mask, HASHLEN);
   sha256_update(&sha_256_ctx, inited_key, HASHLEN);
   sha256_final(&sha_256_ctx, val.hash);
   return val.u64 % sizeof(Keypool);
}

int get_possible_key_location_in_keypool(
   const EncMetadata unlocked_metadata,
   uint16_t          keypool_location_candidate,
   int               key_stage) {
#define GET_BIT(n, x) (((n) >> (x)) & 1)

   uint8_t index;
   fill_secure_random_bits(&index, sizeof(index));
   index = index % 2;
   for (unsigned i = 0; i < 2; i ++) {
      for (int cur_key_index = 0; cur_key_index < KEY_SLOT_COUNT; cur_key_index ++) {
         // if key stores under this slot.
         if (GET_BIT(unlocked_metadata.keyslot_location_area, cur_key_index) == i && unlocked_metadata.keyslot_level[
                cur_key_index] != 0) {
            // if ! (not overlap)
            if (! (keypool_location_candidate + convert_stage_to_size(key_stage) <= unlocked_metadata.keyslot_location[
                      cur_key_index] ||
                   unlocked_metadata.keyslot_location[cur_key_index] + convert_stage_to_size(
                      unlocked_metadata.keyslot_level[cur_key_index]) <= keypool_location_candidate)) {
               goto CONTINUE;
            }
         }
      }
      return index;
   CONTINUE:
      index = ! index;
   }
   return -1;
}

void fill_random_pattern_in_keypool(Data * data) {
#define PATTERN_LEN 32
   static_assert(PATTERN_LEN < convert_stage_to_size(1), "the shortest key entry must be able to contain the random pattern");

   EncMetadata unlocked_metadata = data->metadata;
   uint64_t    random_pattern[KEY_SLOT_COUNT * 2 - 1];

LOOP:

   fill_secure_random_bits((uint8_t *) random_pattern, sizeof(random_pattern));

   for (unsigned i = 0; i < sizeof(random_pattern) / sizeof(*random_pattern); i ++) {
      unsigned pattern_location = random_pattern[i] % sizeof(Keypool);
      unsigned pattern_level    = random_pattern[i] / ((UINT64_MAX >> 1) + 1);

      // if key stores under this slot.
      for (int slot = 0; slot < KEY_SLOT_COUNT; slot ++) {
         if (unlocked_metadata.keyslot_level[slot] != 0 && GET_BIT(unlocked_metadata.keyslot_location_area, slot) ==
             pattern_level) {
            // if ! (not overlap)
            if (! (pattern_location + PATTERN_LEN /* random fill pattern len */ <= unlocked_metadata.keyslot_location[slot] ||
                   unlocked_metadata.keyslot_location[slot] + convert_stage_to_size(unlocked_metadata.keyslot_level[slot]) <=
                   pattern_location)) {
               goto LOOP;
            }
         }
      }
   }
   for (unsigned i = 0; i < sizeof(random_pattern) / sizeof(*random_pattern); i ++) {
      int pattern_location      = random_pattern[i] % sizeof(Keypool);
      int pattern_location_zone = random_pattern[i] / ((UINT64_MAX >> 1) + 1);
      fill_secure_random_bits(&data->keypool[pattern_location_zone].keypool[pattern_location], PATTERN_LEN);
   }
}

void get_metadata_key_or_disk_key_from_master_key(
   const uint8_t master_key[HASHLEN],
   const uint8_t mask[HASHLEN],
   const uint8_t data$uuid_and_salt[16],
   uint8_t       result_key[],
   size_t        key_size) {
   uint8_t *inter_key = calloc(1, key_size);
   if (!inter_key) {
      perror("malloc");
      exit(1);
   }
   // master_key and mask are HASHLEN=32 bytes. XOR them for the first
   // HASHLEN bytes; Argon2 will extend to key_size bytes in output.
   xor_with_len((key_size < HASHLEN ? key_size : HASHLEN), master_key, mask, inter_key);
   int result = kdf_hash(
      1,
      BASE_MEM_COST * 2,
      PARALLELISM,
      inter_key,
      (int)(key_size < HASHLEN ? key_size : HASHLEN),  // password length
      data$uuid_and_salt,
      16,
      result_key,
      (int)key_size,
      true);
   free(inter_key);
   // shouldn't fail, because m_cost is small enough for KDF.
   if (result != NMOBJ_Enclib_calc_okay) {
      perror("kdf");
      windham_exit(1);
   }
}


void convert_metadata_endianness_to_le(EncMetadata * data$metadata) {
   data$metadata->block_size   = htole16(data$metadata->block_size);
   data$metadata->start_sector = htole64(data$metadata->start_sector);
   data$metadata->end_sector   = htole64(data$metadata->end_sector);
}


void convert_metadata_endianness_to_h(EncMetadata * data$metadata) {
   data$metadata->block_size   = le16toh(data$metadata->block_size);
   data$metadata->start_sector = le64toh(data$metadata->start_sector);
   data$metadata->end_sector   = le64toh(data$metadata->end_sector);
}


bool unlock_metadata_using_master_key(Data * data, const uint8_t master_key[HASHLEN]) {
   uint8_t key[HASHLEN];

    get_metadata_key_or_disk_key_from_master_key(master_key, data->master_key_mask, data->uuid_and_salt, key, HASHLEN);

   struct AES_ctx ctx;
   AES_init_ctx_iv(&ctx, key, data->master_key_mask);

   AES_CBC_decrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(EncMetadata));
   if (le64toh(data->metadata.check_key_magic_number) != CHECK_KEY_MAGIC_NUMBER) {
      return false;
   }

   convert_metadata_endianness_to_h(&data->metadata);
   return true;
}

void lock_metadata_using_master_key(Data * data, const uint8_t master_key[HASHLEN]) {
   uint8_t metadata_key[HASHLEN];

    get_metadata_key_or_disk_key_from_master_key(master_key, data->master_key_mask, data->uuid_and_salt, metadata_key, HASHLEN);

   struct AES_ctx ctx;
   AES_init_ctx_iv(&ctx, metadata_key, data->master_key_mask);

   convert_metadata_endianness_to_le(&data->metadata);
   AES_CBC_encrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(EncMetadata));
}


void initialize_new_header(
   Data *        uninitialized_header,
   const uint8_t master_key[HASHLEN],
   const char *  enc_type,
   uint64_t      start_sector,
   uint64_t      end_sector,
   size_t        block_size,
   uint64_t      aux_sector_size) {
   fill_secure_random_bits((uint8_t *) uninitialized_header, sizeof(*uninitialized_header));

   uninitialized_header->metadata.start_sector = htole64(start_sector);
   uninitialized_header->metadata.end_sector   = htole64(end_sector);
   strcpy(uninitialized_header->metadata.enc_type, enc_type);
   uninitialized_header->metadata.block_size = htole16(block_size);

   memset(uninitialized_header->metadata.keyslot_key, 0, sizeof(uninitialized_header->metadata.keyslot_key));
   memset(uninitialized_header->metadata.keyslot_level, 0, sizeof(uninitialized_header->metadata.keyslot_level));
   memset(uninitialized_header->metadata.keyslot_location, 0, sizeof(uninitialized_header->metadata.keyslot_location));
   uninitialized_header->metadata.keyslot_location_area = 0;

   uninitialized_header->metadata.start_aux_sector = aux_sector_size == 0 ? 0 : HEADER_AREA_IN_SECTOR;
   uninitialized_header->metadata.aux_sector_size = aux_sector_size;
   uninitialized_header->metadata.disk_key_size_in_bits_div_64 = (uint8_t)(DEFAULT_DISK_KEY_SIZE_BYTES * 8 / 64);

   uninitialized_header->metadata.check_key_magic_number = htole64(CHECK_KEY_MAGIC_NUMBER);
   set_master_key_check(uninitialized_header, master_key);
}


void assign_new_header_iv(Data * unlocked_header, const bool is_assign_new_head) {
   if (is_assign_new_head) {
      fill_secure_random_bits(unlocked_header->head, sizeof(unlocked_header->head));
   }
   fill_secure_random_bits(unlocked_header->master_key_mask, sizeof(unlocked_header->master_key_mask));
}


void register_key_slot_as_used2(
   EncMetadata *  metadata,
   const uint8_t  inited_key[HASHLEN],
   const uint16_t keypool_location_candidate,
   const int      index,
   const int      level,
   const int      free_slot_index) {
#define SET_BIT(n, x, y) ((n & ~(1ULL << (x))) | (((uint64_t)(y) & 1) << (x)))
   metadata->keyslot_location_area = SET_BIT(metadata->keyslot_location_area, free_slot_index, index);
   memcpy(metadata->keyslot_key[free_slot_index], inited_key, HASHLEN);
   metadata->keyslot_level[free_slot_index]    = level;
   metadata->keyslot_location[free_slot_index] = keypool_location_candidate;
}


void suspend_encryption(Data * encrypted_header, const uint8_t master_key[HASHLEN]) {
   // tag header as suspended
   memcpy(encrypted_header->hint.windham_partition_magic_area, suspend_hint_tag, sizeof(suspend_hint_tag));
   uint8_t key[HASHLEN];

   get_metadata_key_or_disk_key_from_master_key(
      master_key,
      encrypted_header->master_key_mask,
      encrypted_header->uuid_and_salt,
      key, HASHLEN);

   struct AES_ctx ctx;
   AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
   AES_CBC_decrypt_buffer(
      &ctx,
      (uint8_t *) &encrypted_header->metadata,
      offsetof(EncMetadata, WINDHAM_METADATA_ENC_BORDER));

   xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
   convert_metadata_endianness_to_h(&encrypted_header->metadata);
}


bool resume_encryption(
   Data *  encrypted_header,
   uint8_t master_key[HASHLEN]) {
   uint8_t        key[HASHLEN];

   // untag header as suspended.
   fill_secure_random_bits(encrypted_header->hint.windham_partition_magic_area, sizeof(encrypted_header->hint.windham_partition_magic_area));

   xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);

   convert_metadata_endianness_to_le(&encrypted_header->metadata);

   get_metadata_key_or_disk_key_from_master_key(
      master_key,
      encrypted_header->master_key_mask,
      encrypted_header->uuid_and_salt,
      key, HASHLEN);

   struct AES_ctx ctx;
   AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
   AES_CBC_encrypt_buffer(
      &ctx,
      (uint8_t *) &encrypted_header->metadata,
      offsetof(EncMetadata, WINDHAM_METADATA_ENC_BORDER));

   static_assert(offsetof(EncMetadata, WINDHAM_METADATA_ENC_BORDER) % AES_BLOCKLEN == 0, "");

   uint8_t * metadata_cpy_encrypted = malloc(sizeof(EncMetadata));

   memcpy(metadata_cpy_encrypted, &encrypted_header->metadata, sizeof(EncMetadata));

   if (unlock_metadata_using_master_key(encrypted_header, master_key) == false) {
      free(metadata_cpy_encrypted);
      return false;
   }
   memcpy(&encrypted_header->metadata, metadata_cpy_encrypted, sizeof(EncMetadata));
   free(metadata_cpy_encrypted);
   return true;
}

#endif // #ifndef INCL_ENCLIB
