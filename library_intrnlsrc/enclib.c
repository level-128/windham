#ifndef INCL_ENCLIB
#define INCL_ENCLIB

#include "windham_const.h"

#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/sysinfo.h>

#include "aes.h"
#include "argon2B3.h"
#include "sha256.h"
#include "srclib.c"
#include <threads.h>
#include <float.h>


uint64_t bounds[][2] = {
  {126, 171},
  {342, 464},
  {932, 1262},
  {2533, 3429},
  {6887, 9319},
  {18722, 25331},
  {50893, 68856},
  {138341, 187169},
  {376051, 508776},
  {1022213, 1382995},
  {2778664, 3759370},
  {7553193, 10219028},
  {20531709, 27778196},
  {55810973, 75508965},
  {151709955, 205254647},
  {412390416, 557939975},
  {1120993374, 1516638095},
  {3047175919, 4122649774},
  {8283082929, 11206523964},
  {22515753810, 30462490450},
  {61204164436, 82805634238},
  {166370168014, 225089050844},
  {452241004511, 611855476693},
  {1229318504647, 1663195623936},
  {3341634152572, 4521034441716},
  {9083503394295, 12289445768754}
};


const uint8_t head[16] = {'\xe8', '\xb4', '\xb4', '\xe8', '\xb4', '\xb4', 'l', 'e', 'v', 'e', 'l', '-', '1', '2', '8', '!'};

void fill_secure_random_bits(uint8_t * address, size_t size) {
  ssize_t size_filled;

 FILL_BY_GETRANDOM:
  size_filled = getrandom(address, size, 0);
  if (size_filled != (long)size) {
    if (errno == EINTR) { // interrupted by signal
      goto FILL_BY_GETRANDOM;
    } 
    perror("getrandom");
    windham_exit(1);
  }
}


extern inline bool is_header_suspended(const Data encrypted_header) {
  return memcmp(encrypted_header.head, head, 16) == 0;
}


void generate_memory_req_from_master_key_mask(const uint8_t master_key_mask[HASHLEN], uint64_t mem[KEY_SLOT_EXP_MAX]) {
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, master_key_mask);
  uint8_t buffer[AES_BLOCKLEN] = {0};
  static_assert(KEY_SLOT_EXP_MAX % 2 == 0, "KEY_SLOT_EXP_MAX not devideable by 2");

  for (int i = 0; i < KEY_SLOT_EXP_MAX; i += 2) {
    buffer[0] = i / 2;
    AES_ECB_encrypt(&ctx, buffer);
    memcpy(&mem[i], buffer, AES_BLOCKLEN);
    memset(buffer, 0, AES_BLOCKLEN);
    mem[i]     = (mem[i] % (bounds[i][1] - bounds[i][0] + 1)) + bounds[i][0];
    mem[i + 1] = (mem[i + 1] % (bounds[i + 1][1] - bounds[i + 1][0] + 1)) + bounds[i + 1][0];
  }
}


enum {
  NMOBJ_Enclib_calc_okay,
  // okay
  NMOBJ_Enclib_gen_okay_time_reached,
  // okay
  NMOBJ_Enclib_gen_okay_mem_reached,
  // okay
  NMOBJ_Enclib_gen_okay_level_reached,
  // okay
  NMOBJ_Enclib_calc_failed_no_time,
  // no correct pw, no time
  NMOBJ_Enclib_calc_failed_level_exceeded,
  // no correct pw, > max_level
  NMOBJ_Enclib_calc_failed_reached_max_mem,
  // no correct pw, max mem reached
  NMOBJ_Enclib_alloc_failed_policy_nolock,
  // no correct pw, max mem reached, cannot lock memory when is_allow_nolock == false
  NMOBJ_Enclib_alloc_failed_lock_error,
  // no correct pw, sys error, cannot lock memory
  NMOBJ_Enclib_alloc_failed_no_free_mem,
  // no correct pw, sys error, no memory
} allocate_memory_for_KDF(const size_t target_mem, bool is_allow_nolock, uint8_t ** result) {

  if (target_mem > 1 << 23){ // larger than 8MiB
    struct sysinfo info;

    if (sysinfo(&info) != -1) {
      size_t real_free_mem = info.freeram - info.totalram / 100 + 131072;
      if (is_allow_nolock){
	real_free_mem += info.freeswap;
      }
      
      if (real_free_mem < target_mem){
	if (is_allow_nolock){
	  return NMOBJ_Enclib_alloc_failed_no_free_mem;
	} else {
	  if (real_free_mem + info.freeswap < target_mem){
	    return NMOBJ_Enclib_alloc_failed_no_free_mem;
	  } else {
	    return NMOBJ_Enclib_alloc_failed_policy_nolock;
	  }
	}

      }
    }
  }
  
  const int prot  = PROT_READ | PROT_WRITE;
  const int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;

  *result = mmap(NULL, target_mem, prot, flags, -1, 0);
  if (*result == MAP_FAILED) {
    if (errno == ENOMEM) {
      return NMOBJ_Enclib_alloc_failed_no_free_mem;
    }
  }
  if (is_allow_nolock == false) {
    if (mlock(*result, target_mem) == -1) {
      if (errno == EAGAIN) { // no mem
	munmap(*result, target_mem);
	return NMOBJ_Enclib_alloc_failed_policy_nolock;
      } else if (errno == EPERM || errno == ENOMEM) {
	//   ENOMEM: the caller had a nonzero
	//   RLIMIT_MEMLOCK soft resource limit, but tried to lock more
	//   memory than the limit permitted.  This limit is not
	//   enforced if the process is privileged (CAP_IPC_LOCK).
	//   EPERM: The caller is not privileged, but needs privilege
	//   (CAP_IPC_LOCK) to perform the requested operation.
	munmap(*result, target_mem);
	return NMOBJ_Enclib_alloc_failed_lock_error;
      }
    }
  }
  return NMOBJ_Enclib_calc_okay;
}

void free_allocate_memory_for_KDF(const size_t target_mem, uint8_t * mem) {
  munmap(mem, target_mem);
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


bool read_key_from_data_one_level(
				  Data     data,
				  uint64_t mem,
				  uint8_t  inited_keys_cpy[2][HASHLEN],
				  uint16_t keypool_loc,
				  bool     is_allow_nolock,
				  int      i,
				  uint8_t  ret_master_key[HASHLEN],
				  int *    ret_key_zone,
				  int *    ret_result) {
  uint8_t * KDF_memory;
  *ret_result = allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem, 1), is_allow_nolock, &KDF_memory);
  if (*ret_result != NMOBJ_Enclib_calc_okay) {
    return false;
  }
  for (int j = 0; j < 2; j ++) {
    argon2b3_hash(
		  KDF_memory,
		  1,
		  mem,
		  PARALLELISM,
		  inited_keys_cpy[j],
		  HASHLEN,
		  get_slot_loc(data, j, keypool_loc)->hash_salt,
		  cal_salt_size(i),
		  ret_master_key,
		  HASHLEN,
		  Argon2B3_id);
    memcpy(inited_keys_cpy[j], ret_master_key, HASHLEN);
    xor_with_len(HASHLEN, ret_master_key, get_slot_loc(data, j, keypool_loc)->key_mask, ret_master_key);
    if (check_master_key_check(data, ret_master_key)) {
      free_allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem, 1), KDF_memory);
      *ret_key_zone = j;
      return true;
    }
  }
  free_allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem, 1), KDF_memory);
  *ret_result = NMOBJ_Enclib_calc_okay;
  return false;
}


#include <pthread.h>

typedef struct {
  uint8_t * KDF_memory;
  int       i;
  int       j;
  Data *    data;
  uint64_t  mem;
  uint8_t * inited_keys_cpy;
  uint8_t * ret_master_key;
  uint16_t  keypool_loc;
  bool      is_allow_nolock;
} Read_key_from_data_one_level_mt_thread_function_args;

void * read_key_from_data_one_level_mt_thread_function(void * arg) {
  uint8_t                                                tmp_master_key[HASHLEN];
  Read_key_from_data_one_level_mt_thread_function_args * args = arg;
  argon2b3_hash(
		args->KDF_memory,
		1,
		args->mem,
		PARALLELISM,
		args->inited_keys_cpy,
		HASHLEN,
		get_slot_loc((*args->data), args->j, args->keypool_loc)->hash_salt,
		cal_salt_size(args->i),
		tmp_master_key,
		HASHLEN,
		Argon2B3_id);
  memcpy(args->inited_keys_cpy, tmp_master_key, HASHLEN);
  xor_with_len(HASHLEN, tmp_master_key, get_slot_loc((*args->data), args->j, args->keypool_loc)->key_mask, tmp_master_key);
  if (check_master_key_check(*args->data, tmp_master_key)) {
    memcpy(args->ret_master_key, tmp_master_key, HASHLEN);
    return (void *) 1;
  }
  return NULL;
}

#define STACK_SIZE (1024 * 32)

bool read_key_from_data_one_level_mt(
				     Data     data,
				     uint64_t mem,
				     uint8_t  inited_keys_cpy[2][HASHLEN],
				     uint16_t keypool_loc,
				     bool     is_allow_nolock,
				     int      i,
				     uint8_t  ret_master_key[HASHLEN],
				     int *    ret_key_zone,
				     int *    ret_result) {
  uint8_t *   KDF_memory;
  static bool is_mt_mem_okay = true;
  if (is_mt_mem_okay) {
    *ret_result = allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem, 1) * 2, is_allow_nolock, &KDF_memory);
    if (*ret_result != NMOBJ_Enclib_calc_okay) {
      // fallback to st
      is_mt_mem_okay = false;
    }
  }
  if (! is_mt_mem_okay) {
    return read_key_from_data_one_level(data, mem, inited_keys_cpy, keypool_loc, is_allow_nolock, i, KDF_memory, ret_key_zone, ret_result);
  }


  Read_key_from_data_one_level_mt_thread_function_args args[2];
  for (int j = 0; j < 2; j ++) {
    args[j].data            = &data;
    args[j].KDF_memory      = KDF_memory + argon2b3_get_ctx_memory_size(mem, 1) * j;
    args[j].i               = i;
    args[j].j               = j;
    args[j].mem             = mem;
    args[j].inited_keys_cpy = inited_keys_cpy[j];
    args[j].keypool_loc     = keypool_loc;
    args[j].is_allow_nolock = is_allow_nolock;
    args[j].ret_master_key  = ret_master_key;
  }
  pthread_t      thread;
  pthread_attr_t attr;
  size_t         stack_size = 1024 * 64;

  if (stack_size < PTHREAD_STACK_MIN){
    stack_size = PTHREAD_STACK_MIN;
  }
   
  pthread_attr_init(&attr);

  if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
    perror("pthread_attr_setstacksize");
    windham_exit(1);
  }

  if (pthread_attr_setstack(&attr, alloca(stack_size), stack_size) != 0) {
    perror("pthread_attr_setstack");
    windham_exit(1);
  }

  if (pthread_create(&thread, &attr, read_key_from_data_one_level_mt_thread_function, &args[1]) != 0) {
    perror("pthread_create");
    windham_exit(1);
  }

  const uintptr_t return_val = (uintptr_t) read_key_from_data_one_level_mt_thread_function(&args[0]);
  uintptr_t       thread_return_val;
  if (pthread_join(thread, (void *) &thread_return_val) != 0) {
    perror("pthread_join");
    windham_exit(1);
  }
  pthread_attr_destroy(&attr);
  free_allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem, 1), KDF_memory);

  if (return_val) {
    *ret_key_zone = 0;
    return true;
  } if (thread_return_val) {
    *ret_key_zone = 1;
    return true;
  }
  *ret_result = NMOBJ_Enclib_calc_okay;
  return false;
}


int read_key_from_data(
		       Data          data,
		       const uint8_t inited_key[HASHLEN],
		       uint16_t      keypool_loc,
		       double        target_time,
		       size_t        target_mem,
		       const uint8_t max_level,
		       bool          is_allow_nolock,
		       int *         ret_key_zone,
		       int *         ret_level,
		       uint8_t       ret_master_key[HASHLEN]) {
  uint64_t mem[KEY_SLOT_EXP_MAX];
  generate_memory_req_from_master_key_mask(data.master_key_mask, mem);

  uint8_t inited_keys_cpy[2][HASHLEN];
  memcpy(inited_keys_cpy[0], inited_key, HASHLEN);
  memcpy(inited_keys_cpy[1], inited_key, HASHLEN);

  struct timespec start, current;
  double          elapsed_time = 0.0;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

  for (int i = 0; i < KEY_SLOT_EXP_MAX; i ++) {
    if (i == max_level) {
      *ret_level = i;
      return NMOBJ_Enclib_calc_failed_level_exceeded;
    }
    if (mem[i] >= target_mem) {
      *ret_level = i;
      return NMOBJ_Enclib_calc_failed_reached_max_mem;
    }

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &current);
    elapsed_time = (current.tv_sec - start.tv_sec) +
      (current.tv_nsec - start.tv_nsec) / 1e9;
    if (elapsed_time > target_time * 2) {
      *ret_level = i;
      return NMOBJ_Enclib_calc_failed_no_time;
    }

    int result;
    if (read_key_from_data_one_level_mt(
					data,
					mem[i],
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
  __builtin_unreachable();
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

  uint64_t mem[KEY_SLOT_EXP_MAX];
  generate_memory_req_from_master_key_mask(data.master_key_mask, mem);

  uint8_t inited_key_cpy[HASHLEN];
  memcpy(inited_key_cpy, inited_key, HASHLEN);

  struct timespec start, current;
  double          elapsed_time = 0.0;

  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

  for (int i = 0; i < KEY_SLOT_EXP_MAX; i ++) {
    if (i == max_level) {
      *ret_level = i;
      return_val = NMOBJ_Enclib_gen_okay_level_reached;
      goto BREAK_LOOP;
    }
    if (mem[i] >= target_mem) {
      *ret_level = i;
      return_val = NMOBJ_Enclib_gen_okay_mem_reached;
      goto BREAK_LOOP;
    }
    if (target_time != DBL_MAX) {
      // if user sets target_mem or max_level, then not using default time constrains
      clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &current);
      elapsed_time = (current.tv_sec - start.tv_sec) +
	(current.tv_nsec - start.tv_nsec) / 1e9;
      if (elapsed_time > target_time) {
	*ret_level = i;
	return_val = NMOBJ_Enclib_gen_okay_time_reached;
	goto BREAK_LOOP;
      }
    }

    uint8_t * KDF_memory;
    int       result = allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem[i], 1), is_allow_nolock, &KDF_memory);
    if (result != NMOBJ_Enclib_calc_okay) { // error and return
      *ret_level = i;
      return result;
    }
    uint8_t hash_result[HASHLEN];
    argon2b3_hash(
		  KDF_memory,
		  1,
		  mem[i],
		  PARALLELISM,
		  inited_key_cpy,
		  HASHLEN,
		  ret_target_slot->hash_salt,
		  cal_salt_size(i),
		  hash_result,
		  HASHLEN,
		  Argon2B3_id);
    memcpy(inited_key_cpy, hash_result, HASHLEN);
    free_allocate_memory_for_KDF(argon2b3_get_ctx_memory_size(mem[i], 1), KDF_memory);
  }
  __builtin_unreachable();

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
  for (int i = 0; i < 2; i ++) {
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

  fill_secure_random_bits((uint8_t *)random_pattern, sizeof(random_pattern));
      
  for (unsigned i = 0; i < sizeof(random_pattern) / sizeof(*random_pattern); i ++) {
    int pattern_location =  random_pattern[i] % sizeof(Keypool);
    int pattern_level = random_pattern[i] / ((UINT64_MAX >> 1) + 1);
	
    // if key stores under this slot.
    for (int slot = 0; slot < KEY_SLOT_COUNT; slot ++) {
      if (unlocked_metadata.keyslot_level[slot] != 0 && GET_BIT(unlocked_metadata.keyslot_location_area, slot) == pattern_level) {
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
    int pattern_location =  random_pattern[i] % sizeof(Keypool);
    int pattern_location_zone = random_pattern[i] / ((UINT64_MAX >> 1) + 1);
    fill_secure_random_bits(&data->keypool[pattern_location_zone].keypool[pattern_location], PATTERN_LEN);
  }
}

void get_metadata_key_or_disk_key_from_master_key(
						  const uint8_t master_key[HASHLEN],
						  const uint8_t mask[HASHLEN],
						  const uint8_t data$uuid_and_salt[16],
						  uint8_t       key[HASHLEN]) {
  uint8_t inter_key[HASHLEN];
  xor_with_len(HASHLEN, master_key, mask, inter_key);
  argon2b3_hash_alloced(
			1,
			BASE_MEM_COST * 2,
			PARALLELISM,
			inter_key,
			HASHLEN,
			data$uuid_and_salt,
			16,
			key,
			HASHLEN,
			Argon2B3_id);
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

  get_metadata_key_or_disk_key_from_master_key(master_key, data->master_key_mask, data->uuid_and_salt, key);

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
  uint8_t key[HASHLEN];

  get_metadata_key_or_disk_key_from_master_key(master_key, data->master_key_mask, data->uuid_and_salt, key);

  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, data->master_key_mask);

  convert_metadata_endianness_to_le(&data->metadata);
  AES_CBC_encrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(EncMetadata));
}


void initialize_new_header(
			   Data *        uninitialized_header,
			   const uint8_t master_key[HASHLEN],
			   const char *  enc_type,
			   size_t        start_sector,
			   size_t        end_sector,
			   size_t        block_size) {
  fill_secure_random_bits((uint8_t *) uninitialized_header, sizeof(*uninitialized_header));

  uninitialized_header->metadata.start_sector = htole64(start_sector);
  uninitialized_header->metadata.end_sector   = htole64(end_sector);
  strcpy(uninitialized_header->metadata.enc_type, enc_type);
  uninitialized_header->metadata.block_size = htole16(block_size);

  memset(uninitialized_header->metadata.keyslot_key, 0, sizeof(uninitialized_header->metadata.keyslot_key));
  memset(uninitialized_header->metadata.keyslot_level, 0, sizeof(uninitialized_header->metadata.keyslot_level));
  memset(uninitialized_header->metadata.keyslot_location, 0, sizeof(uninitialized_header->metadata.keyslot_location));
  uninitialized_header->metadata.keyslot_location_area = 0;

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
#define SET_BIT(n, x, y) ((n & ~(1U << (x))) | ((y & 1) << (x)))
  metadata->keyslot_location_area = SET_BIT(metadata->keyslot_location_area, free_slot_index, index);
  memcpy(metadata->keyslot_key[free_slot_index], inited_key, HASHLEN);
  metadata->keyslot_level[free_slot_index]    = level;
  metadata->keyslot_location[free_slot_index] = keypool_location_candidate;
}


void suspend_encryption(Data * encrypted_header, const uint8_t master_key[HASHLEN]) {
  // tag header as suspended
  memcpy(encrypted_header->head, head, sizeof(head));
  uint8_t key[HASHLEN];

  get_metadata_key_or_disk_key_from_master_key(
					       master_key,
					       encrypted_header->master_key_mask,
					       encrypted_header->uuid_and_salt,
					       key);

  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
  AES_CBC_decrypt_buffer(
			 &ctx,
			 encrypted_header->metadata.disk_key_mask, // first element
			 (intptr_t) encrypted_header->metadata.keyslot_key - (intptr_t) encrypted_header->metadata.disk_key_mask);

  xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
  convert_metadata_endianness_to_h(&encrypted_header->metadata);
}


bool resume_encryption(
		       Data *  encrypted_header,
		       uint8_t master_key[HASHLEN]) {
  uint8_t        key[HASHLEN];
  struct AES_ctx ctx;

  // untag header as suspended.
  fill_secure_random_bits(encrypted_header->head, sizeof(encrypted_header->head));

  xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
  convert_metadata_endianness_to_le(&encrypted_header->metadata);

  get_metadata_key_or_disk_key_from_master_key(
					       master_key,
					       encrypted_header->master_key_mask,
					       encrypted_header->uuid_and_salt,
					       key);
   
  AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
  AES_CBC_encrypt_buffer(
			 &ctx,
			 encrypted_header->metadata.disk_key_mask, // first element
			 (intptr_t) encrypted_header->metadata.keyslot_key - (intptr_t) encrypted_header->metadata.disk_key_mask);

  uint8_t metadata_cpy_decrypted[sizeof(EncMetadata) + sizeof(encrypted_header->_metadata_aes_padding)];
   
  memcpy(&metadata_cpy_decrypted, &encrypted_header->metadata, sizeof(EncMetadata) +
	 sizeof(encrypted_header->_metadata_aes_padding));
  if (unlock_metadata_using_master_key(encrypted_header, master_key) == false){
    return false;
  }
  memcpy(&encrypted_header->metadata, &metadata_cpy_decrypted, sizeof(EncMetadata) +
	 sizeof(encrypted_header->_metadata_aes_padding));
  return true;
}

#endif // #ifndef INCL_ENCLIB
