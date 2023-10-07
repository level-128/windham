#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>


#define KEY_SLOT_COUNT 6
#define KEY_SLOT_EXP_MAX 20
#define HASHLEN 32
#define BASE_MEM_COST 64
#define PARALLELISM 4
#define DEFAULT_ENC_TARGET_TIME 1
#define DEFAULT_DISK_ENC_MODE "aes-xts-plain64"
#define CHECK_KEY_MAGIC_NUMBER 0x1373112813731128
#define DEFAULT_TARGET_TIME 1
#define MAX_UNLOCK_TIME_FACTOR 4


#define ECB 0
#define CTR 0

#include "print.c"
#include "argon2.h"
#include "aes.h"

#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif

#if KEY_SLOT_EXP_MAX % 4 != 0
	#error "KEY_SLOT_EXP_MAX must devideable by 4, ensuring Key_slot is AES blocksize alligned."
#endif

const uint64_t exp_val[] = {1, 3, 7, 20, 55, 148, 403, 1097, 2981, 8103, 22026, 59874, 162755, 442413, 1202604,
									 3269017, 8886111, 24154953, 65659969, 178482301, 485165195};


FILE * random_fd;

typedef struct __attribute__((packed)) {
	uint8_t hash_salt[HASHLEN]; // 256b
	uint8_t len_exp[KEY_SLOT_EXP_MAX][4]; // 32b each
	uint8_t key_mask[HASHLEN]; // 256b
} Key_slot;

typedef struct __attribute__((packed)) {
	uint8_t inited_key[KEY_SLOT_COUNT][HASHLEN];
	uint8_t all_key_mask[KEY_SLOT_COUNT][HASHLEN];
	bool key_slot_is_used[KEY_SLOT_COUNT];
	uint8_t disk_key_mask[HASHLEN];
	uint64_t start_sector;
	uint64_t end_sector;  // in sector
	char enc_type[32];
	uint64_t check_key_magic_number;
} Metadata;

typedef struct __attribute__((packed)) STR_data {
	__attribute__((unused)) uint8_t head[16]; // '\xe8' '\xb4' '\xb4' '\xe8' '\xb4' '\xb4' 'l' 'e' 'v' 'e' 'l' '-' '1' '2' '8' '!'
	Metadata metadata;
	__attribute__((unused)) uint8_t AES_align[
			(AES_BLOCKLEN - (sizeof(Metadata) % AES_BLOCKLEN)) % AES_BLOCKLEN];
	uint8_t master_key_mask[HASHLEN];
	Key_slot keys[KEY_SLOT_COUNT];
} Data;

#pragma once

static __attribute_maybe_unused__ uint64_t rdtsc() {
#if defined(__amd64__) || defined(__x86_64__)
	uint64_t rax, rdx;
	__asm__ __volatile__("rdtsc" : "=a"(rax), "=d"(rdx) : :);
	return (rdx << 32) | rax;
#endif
}

void print_hex_array(size_t length, const uint8_t arr[length]) {
	for (size_t i = 0; i < length; ++i) {
		printf("%02x ", arr[i]);
	}
	printf("\n");
}

void init_random_generator(char * generator_addr) {
	random_fd = fopen(generator_addr, "r");
	if (random_fd == NULL) {
		print_error("Failed to open", generator_addr);
	}
}

void fill_secure_random_bits(uint8_t * address, size_t size) {
	size_t read_size = fread(address, 1, size, random_fd);
	if (read_size != size) {
		print_error("IO error while reading random generator.");
	}
}

void xor_with_len(size_t length, const uint8_t a[length], const uint8_t b[length], uint8_t c[length]) {
	for (size_t i = 0; i < length; i++) {
		c[i] = a[i] ^ b[i];
	}
}

void generate_random_numbers(uint8_t x, uint8_t numbers[4]) {
	if (x == 0) {
		memset(numbers, 0, 4);
		return;
	}
	uint8_t rand1 = random();
	uint8_t rand2 = random();
	
	numbers[0] = x + ((rand1 + rand2) % x);
	numbers[1] = x - ((rand1 - rand2) % x);
	numbers[2] = x + ((-rand1 + rand2) % x);
	numbers[3] = x - ((-rand1 - rand2) % x);
	
}


void write_or_read_mem_count_from_len_exp_and_update_salt(Key_slot * key_slot, const uint8_t hash[HASHLEN], uint_fast8_t len_exp_index,
																			 uint8_t salt[], uint64_t * mem_size, bool is_write) {
//	print("read:", (uint32_t) *key_slot->len_exp[len_exp_index]);
//	print_hex_array(hash, HASHLEN);
	uint8_t plain_text[4];
	if (is_write) {
		uint64_t mem_size_write = *mem_size / exp_val[len_exp_index];
		generate_random_numbers(mem_size_write, plain_text);
		xor_with_len(sizeof(uint8_t) * 4, hash, plain_text, key_slot->len_exp[len_exp_index]); //
		
		memcpy(&salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], key_slot->len_exp[len_exp_index], sizeof(uint8_t) * 4);
		
		// hash has uint8_t[8] len, plain_text and cipher text has uint8_t[4]

	} else {
		memcpy(&salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], key_slot->len_exp[len_exp_index], sizeof(uint8_t) * 4);
		
		xor_with_len(sizeof(uint8_t) * 4, hash, key_slot->len_exp[len_exp_index], plain_text);
		
		*mem_size = (plain_text[0] + plain_text[1] + plain_text[2] + plain_text[3]) / 4;
		*mem_size *= exp_val[len_exp_index];
	}
//	print("write_or_read_mem_count_from_len_exp_and_update_salt", (uint32_t) *plain_text, "enc text:", *mem_size, "with key:", (uint32_t) *hash);
}


void argon2id_hash_calc(const uint8_t pwd[HASHLEN], uint_fast8_t len_exp_index, const uint8_t salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], uint8_t hash[HASHLEN],
								uint_fast32_t m_cost) {
	if (m_cost < BASE_MEM_COST) {
		m_cost = BASE_MEM_COST;
	}
	argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, salt,
							HASHLEN + len_exp_index * sizeof(uint8_t) * 4, hash, HASHLEN);
}


bool calc_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint8_t salt[HASHLEN + KEY_SLOT_EXP_MAX * 4], uint64_t max_mem_size) {
	uint8_t new_pwd[HASHLEN];

	
//	print("calc_key_one_step:", len_exp_index, max_mem_size);
	uint64_t required_mem_size;
	write_or_read_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, &required_mem_size, false);
	if (required_mem_size > max_mem_size) {
		return false;
	}
	argon2id_hash_calc(password_hash, len_exp_index, salt , new_pwd, required_mem_size);
	memcpy(password_hash, new_pwd, HASHLEN);
	return true;
}

void write_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint8_t salt[HASHLEN + KEY_SLOT_EXP_MAX * 4], uint64_t target_mem_size) {
//	print("write_key_one_step:", len_exp_index, target_mem_size);
	uint8_t new_pwd[HASHLEN];
	write_or_read_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, &target_mem_size, true);
	argon2id_hash_calc(password_hash, len_exp_index, salt , new_pwd, target_mem_size);
	memcpy(password_hash, new_pwd, HASHLEN);
}

bool argon2id_iter_hash_one_slot(Key_slot * key_slot, const uint8_t password_hash[HASHLEN], uint8_t new_hash[HASHLEN], uint64_t max_mem_size, bool is_new_pw) {
	uint8_t salt[HASHLEN + KEY_SLOT_EXP_MAX * 4];
	
	memcpy(salt, key_slot->hash_salt, HASHLEN);
	memcpy(new_hash, password_hash, HASHLEN);
	bool is_memory_enough = true;
	for (int_fast8_t i = 0; i < KEY_SLOT_EXP_MAX; i++) {
		if (is_memory_enough) {
			is_memory_enough = calc_key_one_step(key_slot, i, new_hash, salt, max_mem_size);
		}
		if (!is_memory_enough) {
			if (!is_new_pw) {
				return false;
			}
			write_key_one_step(key_slot, i, new_hash, salt, 0);
		}
	}
	return true;
}

bool get_master_key_from_slot(Key_slot * key_slot, const uint8_t password_hash[HASHLEN], uint64_t max_mem_size, uint8_t master_key[HASHLEN]) {
//	print("get_master_key_from_slot pwhash");
//	print_hex_array(password_hash, HASHLEN);
	uint8_t new_hash[HASHLEN];
	if (argon2id_iter_hash_one_slot(key_slot, password_hash, new_hash, max_mem_size, false) == false) {
		return false;
	}

	xor_with_len(HASHLEN, new_hash, key_slot->key_mask, master_key);
	return true;
}

void set_master_key_to_slot(Key_slot * key_slot, const uint8_t password_hash[HASHLEN], uint64_t target_mem_size, const uint8_t master_key[HASHLEN]) {
//	print("set_master_key_to_slot pwhash");
//	print_hex_array(password_hash, HASHLEN);
	
	uint8_t new_hash[HASHLEN];
	argon2id_iter_hash_one_slot(key_slot, password_hash, new_hash, target_mem_size, true);
//	print("set hashed password:");
//	print_hex_array(new_hash, HASHLEN);
	xor_with_len(HASHLEN, new_hash, master_key, key_slot->key_mask);
	
}

void get_metadata_key_or_disk_key_from_master_key(const uint8_t master_key[32], const uint8_t mask[32], uint8_t key[32]) {
	uint8_t inter_key[HASHLEN];
	memcpy(inter_key, master_key, HASHLEN);
	for (int i = 0; i < HASHLEN; i++) {
		inter_key[i] = master_key[i] ^ mask[i];
	}

	argon2id_hash_raw(1, BASE_MEM_COST * 4, PARALLELISM, inter_key, HASHLEN, "level-128!level-128!", strlen("level-128!level-128!"), key, HASHLEN);
	
}

uint64_t calc_initial_pw_hash_and_iter_cnt(const Key_slot unlocked_key, uint8_t * inited_key, uint64_t max_mem_size, double time_limit, uint8_t password_hash[HASHLEN]) {
	// password hash is password_hash_all_slots[KEY_SLOT_COUNT][HASHLEN] if target_slot == -1, else use password_hash[HASHLEN]
//	print("mem-size", max_mem_size, "time-limit", time_limit);

	clock_t start_time, stop_time;
	start_time = clock();
	argon2id_hash_calc(inited_key, 0, unlocked_key.hash_salt, password_hash, BASE_MEM_COST * 8);
	stop_time = clock();
	double time_cost = (double) (stop_time - start_time) / (CLOCKS_PER_SEC);
	double time_cost_per_kib = time_cost / BASE_MEM_COST * 8;
	
	if (time_limit > 0) {
		if (time_limit / time_cost_per_kib < (double) max_mem_size || max_mem_size == 0) {
			max_mem_size = (uint64_t) (time_limit / time_cost_per_kib);
		}
	}
	return max_mem_size;
}

bool operate_metadata_using_master_key(Metadata * metadata, const uint8_t master_key[HASHLEN], const uint8_t metadata_key_mask[HASHLEN]) {
	uint8_t metadata_key[HASHLEN];
	
	get_metadata_key_or_disk_key_from_master_key(master_key, metadata_key_mask, metadata_key);
	xor_with_len(HASHLEN, metadata_key, metadata_key_mask, metadata_key);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, metadata_key, metadata_key_mask);
	
	
	if (metadata->check_key_magic_number != CHECK_KEY_MAGIC_NUMBER) {
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) metadata, sizeof(Metadata));
		return metadata->check_key_magic_number == CHECK_KEY_MAGIC_NUMBER;
	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) metadata, sizeof(Metadata));
		return true;
	}
}


void operate_key_slot_using_inited_key(Key_slot * keys, const uint8_t inited_key[HASHLEN], const uint8_t master_key_mask[HASHLEN], bool is_decrypt){
//	print("operate_key_slot_using_inited_key , decrypt:", is_decrypt);
//	print_hex_array(HASHLEN, (const uint8_t *) keys);
	uint8_t temp_key[HASHLEN];
	
	xor_with_len(HASHLEN, inited_key, master_key_mask, temp_key);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, temp_key, master_key_mask);
//	print_hex_array(HASHLEN, (const uint8_t *) inited_key);
	
	if (is_decrypt){
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) keys, sizeof(Key_slot));
	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) keys, sizeof(Key_slot));
	}
//	print_hex_array(HASHLEN, (const uint8_t *) keys);
//	print("");
}

void operate_all_keyslots(Key_slot keys[KEY_SLOT_COUNT], const uint8_t inited_key[KEY_SLOT_COUNT][HASHLEN], const uint8_t master_key_mask[HASHLEN], bool is_decrypt){
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		operate_key_slot_using_inited_key(&keys[i], inited_key[i], master_key_mask, is_decrypt);
	}
}

void initialize_new_header(Data * uninitialized_header, const char * enc_type, size_t start_sector, size_t end_sector) {
	fill_secure_random_bits((uint8_t *) uninitialized_header, sizeof(Data));
	
//	operate_metadata_using_master_key(&uninitialized_header->metadata, master_key, uninitialized_header->master_key_mask, true);
	memset(uninitialized_header->metadata.key_slot_is_used, false, sizeof(uninitialized_header->metadata.key_slot_is_used));
	if (enc_type != NULL) {
		strcpy(uninitialized_header->metadata.enc_type, enc_type);
	} else {
		strcpy(uninitialized_header->metadata.enc_type, DEFAULT_DISK_ENC_MODE);
	}
	uninitialized_header->metadata.check_key_magic_number = CHECK_KEY_MAGIC_NUMBER;
	
	uninitialized_header->metadata.start_sector = start_sector;
	uninitialized_header->metadata.end_sector = end_sector;
	
	memset(uninitialized_header->metadata.inited_key, 0, sizeof(uninitialized_header->metadata.inited_key));
}

void transform_header(Data * unlocked_header){
	fill_secure_random_bits(unlocked_header->master_key_mask, sizeof(unlocked_header->master_key_mask));
	fill_secure_random_bits(unlocked_header->AES_align, sizeof(unlocked_header->AES_align));
	fill_secure_random_bits(unlocked_header->head, sizeof(unlocked_header->head));
}

void revoke_given_key_slot(Data * initialized_header, int target_slot, bool is_tag_revoke) {
	fill_secure_random_bits(initialized_header->keys[target_slot].key_mask, HASHLEN);
	if (is_tag_revoke){
		memset(initialized_header->metadata.all_key_mask[target_slot], 0, HASHLEN);
	}
}

void register_key_slot_as_used(Data * decrypted_header, uint8_t inited_key[HASHLEN], int slot) {
	decrypted_header->metadata.key_slot_is_used[slot] = true;
	memcpy(decrypted_header->metadata.all_key_mask[slot], decrypted_header->keys[slot].key_mask, HASHLEN);
	memcpy(decrypted_header->metadata.inited_key[slot], inited_key, HASHLEN);
}


enum {
	NMOBJ_select_available_key_slot_NO_FREE_SLOT = -1,
	NMOBJ_select_available_key_slot_PWD_USED = -2,
};


int select_available_key_slot(const Metadata decrypted_metadata, int target_slot, Key_slot keys[KEY_SLOT_COUNT]) {
	target_slot = target_slot == NMOBJ_select_available_key_slot_NO_FREE_SLOT ? rand() % KEY_SLOT_COUNT : target_slot; // NOLINT(*-msc50-cpp)
	if (target_slot != NMOBJ_select_available_key_slot_NO_FREE_SLOT){
		if (decrypted_metadata.key_slot_is_used[target_slot] == false && memcmp(keys[target_slot].key_mask, decrypted_metadata.all_key_mask[target_slot], HASHLEN) != 0){
			return target_slot;
		}
	}
	
	target_slot = NMOBJ_select_available_key_slot_NO_FREE_SLOT;
	
	for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--) {
		if (memcmp(keys, decrypted_metadata.inited_key[i], HASHLEN) == 0){ // is key used
			return NMOBJ_select_available_key_slot_PWD_USED;
		}
		
		if (decrypted_metadata.key_slot_is_used[i] == false) {
			target_slot = i;
		}
	}
	if (target_slot == NMOBJ_select_available_key_slot_NO_FREE_SLOT) {
		for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--) {
			if (memcmp(keys[i].key_mask, decrypted_metadata.all_key_mask[i], HASHLEN) != 0) {
				target_slot = i;
			}
		}
	}
	return target_slot;
}

bool check_master_key_and_slots_revoke(Data * decrypted_header, bool revoked_untagged_slot[KEY_SLOT_COUNT]){
	uint8_t temp[HASHLEN] = {0};
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		revoked_untagged_slot[i] = (memcmp(decrypted_header->keys[i].key_mask, decrypted_header->metadata.all_key_mask[i], HASHLEN) != 0 &&
				(memcmp(temp, decrypted_header->metadata.all_key_mask[i],HASHLEN) != 0) &&
				decrypted_header->metadata.key_slot_is_used[i]);
		if (revoked_untagged_slot[i]){
			memset(decrypted_header->metadata.all_key_mask[i], 0, HASHLEN);
			memset(decrypted_header->metadata.inited_key[i], 0, HASHLEN);
		}
	}
	return true;
}

