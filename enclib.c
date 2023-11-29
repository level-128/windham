#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libintl.h>
#include <math.h>


#define KEY_SLOT_COUNT 6
#define KEY_SLOT_EXP_MAX 20
#define HASHLEN 32
#define BASE_MEM_COST 64
#define PARALLELISM 1
#define DEFAULT_ENC_TARGET_TIME 1
#define DEFAULT_DISK_ENC_MODE "aes-xts-plain64"
#define DEFAULT_TARGET_TIME 1
#define MAX_UNLOCK_TIME_FACTOR 5
#define DEFAULT_BLOCK_SIZE 4096


#define ECB 0
#define CTR 0

#include "srclib.c"
#include "argon2B3.h"
#include "aes.h"
#include "sha256.h"

#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif


#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "This code cannot be compiled on a big-endian machine."
#endif

#if KEY_SLOT_EXP_MAX % 4 != 0
	#error "KEY_SLOT_EXP_MAX must devideable by 4, ensuring Key_slot is AES blocksize alligned."
#endif

#define CHECK_KEY_MAGIC_NUMBER 0x49713d1c7f5dce80

// approx val of \lim_{n -> \inf} ( \sum_{i = 0}^{n} e^i )^{-1} * e^(n + 1)
const double exp_index_diff = 1.64905;

const int exp_PDF_p_bound = 66; // p=0.05

const uint64_t exp_val[] = {1, 3, 7, 20, 55, 148, 403, 1097, 2981, 8103, 22026, 59874, 162755, 442413, 1202604, 3269017, 8886111, 24154953, 65659969, 178482301, 485165195};

const uint8_t head[16] = {'\xe8', '\xb4', '\xb4', '\xe8', '\xb4', '\xb4', 'l', 'e', 'v', 'e', 'l', '-', '1', '2', '8', '!'};

FILE * random_fd;

typedef struct __attribute__((packed)) {
	uint8_t hash_salt[HASHLEN]; // 256b
	uint8_t len_exp[KEY_SLOT_EXP_MAX][4]; // 32b each
	uint8_t key_mask[HASHLEN]; // 256b
} Key_slot;

typedef struct __attribute__((packed)) {
	uint8_t disk_key_mask[HASHLEN];
	uint64_t start_sector;
	uint64_t end_sector;  // in sector
	char enc_type[32];
	uint16_t block_size;
	__attribute__((unused)) uint8_t padding[AES_BLOCKLEN - sizeof(uint16_t)];
	
	// remains encrypted after suspend
	uint8_t keyslot_key[KEY_SLOT_COUNT][HASHLEN];
	uint8_t all_key_mask[KEY_SLOT_COUNT][HASHLEN];
	int8_t key_slot_is_used[KEY_SLOT_COUNT];
	__attribute__((unused)) uint8_t reserved[34];
	uint64_t check_key_magic_number;
} Metadata;

typedef struct __attribute__((packed)) STR_data {
	uint8_t head[16];
	uint8_t uuid_and_salt[16];
	uint8_t master_key_mask[HASHLEN];
	Key_slot keyslots[KEY_SLOT_COUNT];
	Metadata metadata;
	__attribute__((unused)) uint8_t AES_align[
			(AES_BLOCKLEN - (sizeof(Metadata) % AES_BLOCKLEN)) % AES_BLOCKLEN];
} Data;


enum{
	NMOBJ_STEP_OK = -1,
	NMOBJ_STEP_CONTINUE = -2,
	NMOBJ_STEP_ERR_NOMEM = -3,
	NMOBJ_STEP_ERR_TIMEOUT = -4,
	NMOBJ_STEP_ERR_END = -5
};

enum {
	NMOBJ_select_available_key_slot_NO_FREE_SLOT = -1,
	NMOBJ_select_available_key_slot_PWD_USED = -2,
};

#pragma once

void init_enclib(char * generator_addr) {
	FLAG_clear_internal_memory = 0;
	random_fd = fopen(generator_addr, "r");
	if (random_fd == NULL) {
		print_error(_("Failed to initialize random generator."));
	}
}

void fill_secure_random_bits(uint8_t * address, size_t size) {
	size_t read_size = fread(address, 1, size, random_fd);
	if (read_size != size) {
		print_error(_("IO error while reading random generator."));
	}
}

static void xor_with_len(size_t length, const uint8_t a[length], const uint8_t b[length], uint8_t c[length]) {
	for (size_t i = 0; i < length; i++) {
		c[i] = a[i] ^ b[i];
	}
}

extern inline bool is_header_suspended(const Data encrypted_header){
	return memcmp(encrypted_header.head, head, 16) == 0;
}

static uint64_t write_or_read_mem_count_from_len_exp_and_update_salt(Key_slot * key_slot, const uint8_t hash[HASHLEN], uint_fast8_t len_exp_index,
																			 uint8_t salt[], bool is_write, uint8_t new_mem[4]) {
	if (is_write) {
		xor_with_len(sizeof(uint8_t) * 4, hash, new_mem, key_slot->len_exp[len_exp_index]); //
		
		memcpy(&salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], key_slot->len_exp[len_exp_index], sizeof(uint8_t) * 4);
		// hash has uint8_t[8] len, plain_text and cipher text has uint8_t[4]
		print("write mem count:", new_mem[0], new_mem[1], new_mem[2], "for len exp:", len_exp_index, "with hash:", hash[0], hash[1], hash[2]);
		return 0;
		
	} else {
		uint8_t plain_text[4];
		memcpy(&salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], key_slot->len_exp[len_exp_index], sizeof(uint8_t) * 4);
		
		xor_with_len(sizeof(uint8_t) * 4, hash, key_slot->len_exp[len_exp_index], plain_text);
		
		uint64_t mem_size = (plain_text[0] + plain_text[1] + plain_text[2] + plain_text[3]) / 4;
		print("read mem count:", mem_size, "for len exp:", len_exp_index, "with hash:", hash[0], hash[1], hash[2]);
		return mem_size * exp_val[len_exp_index];
	}
}

static int argon2id_hash_calc(const uint8_t pwd[HASHLEN], uint_fast8_t len_exp_index, const uint8_t salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], uint8_t hash[HASHLEN],
								uint_fast32_t m_cost) {
	if (m_cost < BASE_MEM_COST) {
		m_cost = BASE_MEM_COST;
	}
	int ret = argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, salt,
							HASHLEN + len_exp_index * sizeof(uint8_t) * 4, hash, HASHLEN);
	if (ret == ARGON2_MEMORY_ALLOCATION_ERROR){
		return NMOBJ_STEP_ERR_NOMEM;
	} else if (ret != ARGON2_OK) {
		exit(ret);
	}
	print("argon2id_hash_calc res:", hash[0],hash[1],hash[2],hash[3], "pwd: ",  pwd[0],pwd[1],pwd[2],pwd[3]);
	print("len_exp_index:", len_exp_index, "mcost:", m_cost, "salt:", salt[0],salt[1],salt[2],salt[3]);
	return 0;
}

//static void get_random_mem_count_from_avg(uint8_t)
// TODO

static int read_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint8_t salt[HASHLEN + KEY_SLOT_EXP_MAX * 4], uint64_t max_mem_size,
									  uint64_t * required_mem_size) {
	uint8_t new_pwd[HASHLEN];
	
	* required_mem_size = write_or_read_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, false, NULL);
	if (*required_mem_size > max_mem_size) {
		return NMOBJ_STEP_ERR_NOMEM;
	}
	if (argon2id_hash_calc(password_hash, len_exp_index, salt , new_pwd, *required_mem_size) == NMOBJ_STEP_ERR_NOMEM){
		return NMOBJ_STEP_ERR_NOMEM;
	}
	memcpy(password_hash, new_pwd, HASHLEN);
	return *required_mem_size == 0? NMOBJ_STEP_OK : NMOBJ_STEP_CONTINUE;
}

static void operate_key_slot_using_keyslot_key(Key_slot * keyslot, const uint8_t inited_key[32], const uint8_t master_key_mask[32], bool is_decrypt){
	uint8_t temp_key[HASHLEN];
	
	xor_with_len(HASHLEN, inited_key, master_key_mask, temp_key);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, temp_key, master_key_mask);
	
	if (is_decrypt){
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) keyslot, sizeof(Key_slot));
	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) keyslot, sizeof(Key_slot));
	}
}

static int write_to_exp(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint8_t salt[112], double time_left, double time_per_KiB_mem, uint64_t max_mem_size) {
//	print("write_to_exp:", len_exp_index, target_mem_size);
	uint8_t new_mem[4];
	if ( time_left > 0) {
		uint64_t _;
		size_t target_mem_size = ((size_t) (time_left * exp_index_diff / time_per_KiB_mem));
		if (target_mem_size > max_mem_size) {
			target_mem_size = max_mem_size;
		}
		target_mem_size = target_mem_size / exp_val[len_exp_index];
		
		print("target_mem_size:", target_mem_size);
		if (target_mem_size > exp_PDF_p_bound) { //larger than p=0.05
			RAND:;
			int64_t a = rand() % (target_mem_size * 4);
			int64_t b = rand() % (target_mem_size * 4);
			int64_t c = rand() % (target_mem_size * 4);
			if (a > UINT8_MAX || b > UINT8_MAX || c > UINT8_MAX) {
				goto RAND;
			}
			// sort them
			if (a > b) swap(a, b);
			if (b > c) swap(b, c);
			if (a > b) swap(a, b);
			new_mem[0] = a;
			new_mem[1] = b - a;
			new_mem[2] = c - b;
			new_mem[3] = UINT8_MAX - c;
			write_or_read_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, true, new_mem);
			if (read_key_one_step(key_slot, len_exp_index, password_hash, salt, UINT64_MAX, &_) == NMOBJ_STEP_CONTINUE) {
				len_exp_index++;
			}
		}
	}
	
	memset(new_mem, 0, sizeof(new_mem));
	uint8_t new_pwd[HASHLEN];
	write_or_read_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, true, new_mem);
	if (argon2id_hash_calc(password_hash, len_exp_index, salt , new_pwd, 0) == NMOBJ_STEP_ERR_NOMEM){
		exit(1); // not possible. since m_count is BASE_MEM_COST.
	}
	memcpy(password_hash, new_pwd, HASHLEN);
	return 0;
}

static int write_key_to_one_slot(Key_slot * key_slot, uint8_t hash[HASHLEN], uint64_t max_mem_size, double target_time) {
	uint64_t required_mem_size = BASE_MEM_COST;
	
	uint8_t salt[HASHLEN + KEY_SLOT_EXP_MAX * 4];
	memcpy(salt, key_slot->hash_salt, HASHLEN);
	
	clock_t start_time = clock();
	for (int_fast8_t i = 0; i < KEY_SLOT_EXP_MAX; i++) {
		double time_used = ((double) clock() - (double) start_time) / CLOCKS_PER_SEC;
		double time_per_KiB_mem = time_used / (double) required_mem_size / exp_index_diff;
		
		if (time_used > target_time / exp_index_diff) {
			write_to_exp(key_slot, i, hash, salt, target_time - time_used, time_per_KiB_mem, max_mem_size);
			break;
		}

		READ:; // There is a bug from the CLion's syntax parser, don't remove this semicolon.
		int res = read_key_one_step(key_slot, i, hash, salt, max_mem_size, &required_mem_size);
		if (res == NMOBJ_STEP_OK){ // the read memory count is 0
			fill_secure_random_bits(key_slot->len_exp[i], sizeof(key_slot->len_exp[i]));
			goto READ;
		} else if (res == NMOBJ_STEP_ERR_NOMEM) {
			write_to_exp(key_slot, i, hash, salt, 0, 0, UINT64_MAX); // ending
			return NMOBJ_STEP_ERR_NOMEM;
		}
	}
	return 0;
}

int read_key_from_all_slots(Key_slot data$keyslots[KEY_SLOT_COUNT], uint8_t inited_keys[KEY_SLOT_COUNT][HASHLEN], const int slot_seq[KEY_SLOT_COUNT + 1], uint64_t max_mem_size, double target_time) {
	// initialize salt array
	uint8_t salts[KEY_SLOT_COUNT][HASHLEN + KEY_SLOT_EXP_MAX * 4];
	for (int i = 0; slot_seq[i] != -1; i++){
		memcpy(salts[slot_seq[i]], data$keyslots[slot_seq[i]].hash_salt, HASHLEN);
	}
	
	int is_continue_calc_s[KEY_SLOT_COUNT];
	memset(is_continue_calc_s, NMOBJ_STEP_CONTINUE, sizeof(int) * KEY_SLOT_COUNT);
	
	clock_t start_time = clock();
	target_time = slot_seq[1] == -1 ? target_time : target_time * KEY_SLOT_COUNT;
	
	print_ptr_poz(-1, 0);
	
	for (int i = 0; i < KEY_SLOT_EXP_MAX; i++) {
		for (int j = 0; slot_seq[j] != -1; j++) {
			int slot = slot_seq[j];
			if (((double) clock() - (double) start_time) / CLOCKS_PER_SEC > target_time) {
				return NMOBJ_STEP_ERR_TIMEOUT;
			}
			
			if (is_continue_calc_s[slot] != NMOBJ_STEP_ERR_NOMEM) {
				print_ptr_poz(slot, i + 1); // print current slot and progress
				uint64_t _;
				is_continue_calc_s[slot] = read_key_one_step(&data$keyslots[slot], i, inited_keys[slot], salts[slot], max_mem_size, &_);
				if (is_continue_calc_s[slot] == NMOBJ_STEP_ERR_NOMEM) {
					print_ptr_poz(slot, -1);
				} else if (is_continue_calc_s[slot] == NMOBJ_STEP_OK) {
					print_ptr_poz(slot, 0);
					return slot;
				}
			}
		}
	}
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		if (is_continue_calc_s[i] == NMOBJ_STEP_CONTINUE){
			return NMOBJ_STEP_ERR_END;
		}
	}
	return NMOBJ_STEP_ERR_NOMEM;
}

void set_master_key_to_slot(Key_slot * key_slot, const uint8_t inited_key[HASHLEN], uint64_t target_mem_size, double target_time, const uint8_t master_key[HASHLEN]) {
//	print("set_master_key_to_slot pwhash");
//	print_hex_array(inited_key, HASHLEN);
	
	uint8_t new_hash[HASHLEN];
	memcpy(new_hash, inited_key, HASHLEN);
	fill_secure_random_bits((uint8_t *) key_slot, sizeof(Key_slot));
	if (write_key_to_one_slot(key_slot, new_hash, target_mem_size, target_time) == NMOBJ_STEP_ERR_NOMEM){
		print_warning(_("Time quota could not be meet because of insufficient memory, may make the password less secure than the specified value."));
	};
//	print("set hashed password:");
//	print_hex_array(new_hash, HASHLEN);
	xor_with_len(HASHLEN, new_hash, master_key, key_slot->key_mask);
	
}

void get_metadata_key_or_disk_key_from_master_key(const uint8_t master_key[HASHLEN], const uint8_t mask[HASHLEN], const uint8_t data$uuid_and_salt[16], uint8_t key[HASHLEN]) {
	uint8_t inter_key[HASHLEN];
	xor_with_len(HASHLEN, master_key, mask, inter_key);

	argon2id_hash_raw(1, BASE_MEM_COST * 2, PARALLELISM, inter_key, HASHLEN, data$uuid_and_salt, 16, key, HASHLEN);
	
}

bool lock_or_unlock_metadata_using_master_key(Data * data, const uint8_t master_key[HASHLEN]) {
	uint8_t key[HASHLEN];
	
	get_metadata_key_or_disk_key_from_master_key(master_key, data->master_key_mask, data->uuid_and_salt, key);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, data->master_key_mask);
	
	
	if (data->metadata.check_key_magic_number != CHECK_KEY_MAGIC_NUMBER) {
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(Metadata));
		return data->metadata.check_key_magic_number == CHECK_KEY_MAGIC_NUMBER;
	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(Metadata));
		return true;
	}
}

void get_keyslot_key_from_inited_key(const uint8_t inited_key[HASHLEN], const uint8_t data$uuid_and_salt[16], uint8_t keyslot_key[HASHLEN]) {
	SHA256_CTX sha_256_ctx;
	sha256_init(&sha_256_ctx);
	sha256_update(&sha_256_ctx, inited_key, HASHLEN);
	sha256_update(&sha_256_ctx, data$uuid_and_salt, 16);
	sha256_final(&sha_256_ctx, keyslot_key);
//	print("get keyslot key, init key", *(uint64_t *)inited_key, "uuid salt", *(uint64_t *)uuid_and_salt, "keyslot key", *(uint64_t *)keyslot_key);
}

void operate_all_keyslots_using_keyslot_key_in_metadata(Key_slot data$keyslots[KEY_SLOT_COUNT], const uint8_t data$metadata$keyslot_key[KEY_SLOT_COUNT][HASHLEN],
																		  const uint8_t data$master_key_mask[HASHLEN], bool is_decrypt){
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		operate_key_slot_using_keyslot_key(&data$keyslots[i], data$metadata$keyslot_key[i], data$master_key_mask, is_decrypt);
	}
}

void operate_all_keyslots_using_inited_key(Key_slot data$keyslots[KEY_SLOT_COUNT], const uint8_t inited_key[HASHLEN], const uint8_t data$master_key_mask[HASHLEN], const uint8_t data$uuid_and_salt[16],
														 bool is_decrypt){
	uint8_t keyslot_key[HASHLEN];
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		get_keyslot_key_from_inited_key(inited_key, data$uuid_and_salt, keyslot_key);
		operate_key_slot_using_keyslot_key(&data$keyslots[i], keyslot_key, data$master_key_mask, is_decrypt);
	}
}

void initialize_new_header(Data * uninitialized_header, const char * enc_type, size_t start_sector, size_t end_sector, size_t block_size) {
	fill_secure_random_bits((uint8_t *) uninitialized_header, sizeof(Data));
	
	memset(uninitialized_header->metadata.key_slot_is_used, false, sizeof(uninitialized_header->metadata.key_slot_is_used));
	strcpy(uninitialized_header->metadata.enc_type, enc_type);
	uninitialized_header->metadata.check_key_magic_number = CHECK_KEY_MAGIC_NUMBER;
	
	uninitialized_header->metadata.start_sector = start_sector;
	uninitialized_header->metadata.end_sector = end_sector;
	uninitialized_header->metadata.block_size = block_size;
	
	memset(uninitialized_header->metadata.keyslot_key, 0, sizeof(uninitialized_header->metadata.keyslot_key));
}

void assign_new_header_iv(Data * unlocked_header){
	fill_secure_random_bits(unlocked_header->master_key_mask, sizeof(unlocked_header->master_key_mask));
	fill_secure_random_bits(unlocked_header->AES_align, sizeof(unlocked_header->AES_align));
}

void revoke_given_key_slot(Data * initialized_header, int target_slot, bool is_tag_revoke) {
	fill_secure_random_bits(initialized_header->keyslots[target_slot].key_mask, HASHLEN);
	if (is_tag_revoke){
		memset(initialized_header->metadata.all_key_mask[target_slot], 0, HASHLEN);
	}
}

void register_key_slot_as_used(Data * decrypted_header, uint8_t keyslot_key[HASHLEN], int slot) {
	decrypted_header->metadata.key_slot_is_used[slot] = true;
	memcpy(decrypted_header->metadata.all_key_mask[slot], decrypted_header->keyslots[slot].key_mask, HASHLEN);
	memcpy(decrypted_header->metadata.keyslot_key[slot], keyslot_key, HASHLEN);
}

int select_available_key_slot(const Metadata decrypted_metadata, int target_slot, Key_slot data$keyslots[KEY_SLOT_COUNT]) {
	target_slot = target_slot == NMOBJ_select_available_key_slot_NO_FREE_SLOT ? rand() % KEY_SLOT_COUNT : target_slot; // NOLINT(*-msc50-cpp)
	if (target_slot != NMOBJ_select_available_key_slot_NO_FREE_SLOT){
		if (decrypted_metadata.key_slot_is_used[target_slot] == false && memcmp(data$keyslots[target_slot].key_mask, decrypted_metadata.all_key_mask[target_slot], HASHLEN) != 0){
			return target_slot;
		}
	}
	
	target_slot = NMOBJ_select_available_key_slot_NO_FREE_SLOT;
	
	for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--) {
		if (memcmp(data$keyslots, decrypted_metadata.keyslot_key[i], HASHLEN) == 0){ // is key used
			return NMOBJ_select_available_key_slot_PWD_USED;
		}
		
		if (decrypted_metadata.key_slot_is_used[i] == false) {
			target_slot = i;
		}
	}
	if (target_slot == NMOBJ_select_available_key_slot_NO_FREE_SLOT) {
		for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--) {
			if (memcmp(data$keyslots[i].key_mask, decrypted_metadata.all_key_mask[i], HASHLEN) != 0) {
				target_slot = i;
			}
		}
	}
	return target_slot;
}

void check_master_key_and_slots_revoke(Data * decrypted_header, bool revoked_untagged_slot[KEY_SLOT_COUNT]){
	if (!is_header_suspended(*decrypted_header)) { // when the header is suspended, the metadata area
		uint8_t temp[HASHLEN] = {0};
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			revoked_untagged_slot[i] = (memcmp(decrypted_header->keyslots[i].key_mask, decrypted_header->metadata.all_key_mask[i], HASHLEN) != 0 &&
			                            (memcmp(temp, decrypted_header->metadata.all_key_mask[i], HASHLEN) != 0) &&
			                            decrypted_header->metadata.key_slot_is_used[i]);
			if (revoked_untagged_slot[i]) {
				memset(decrypted_header->metadata.all_key_mask[i], 0, HASHLEN);
				memset(decrypted_header->metadata.keyslot_key[i], 0, HASHLEN);
			}
		}
	} else {
		memset(revoked_untagged_slot, 0, sizeof(*revoked_untagged_slot) * KEY_SLOT_COUNT);
	}
}

void suspend_encryption(Data * encrypted_header, const uint8_t master_key[HASHLEN]){
	memcpy(encrypted_header->head, head, sizeof(head));
	uint8_t key[HASHLEN];
	
	get_metadata_key_or_disk_key_from_master_key(master_key, encrypted_header->master_key_mask, encrypted_header->uuid_and_salt, key);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
	AES_CBC_decrypt_buffer(&ctx, encrypted_header->metadata.disk_key_mask, (intptr_t)encrypted_header->metadata.keyslot_key - (intptr_t)encrypted_header->metadata.disk_key_mask);
	
	xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
}

void resume_encryption(Data * encrypted_header, const uint8_t master_key[HASHLEN]){
	fill_secure_random_bits(encrypted_header->head, sizeof(encrypted_header->head));
	uint8_t key[HASHLEN];
	
	xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
	get_metadata_key_or_disk_key_from_master_key(master_key, encrypted_header->master_key_mask, encrypted_header->uuid_and_salt, key);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
	AES_CBC_encrypt_buffer(&ctx, encrypted_header->metadata.disk_key_mask, (intptr_t)encrypted_header->metadata.keyslot_key - (intptr_t)encrypted_header->metadata.disk_key_mask);
}
