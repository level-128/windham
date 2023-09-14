#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>


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
#include "speck.h"
#include "aes.h"
#include "sha256.h"

#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif


FILE * random_fd;

typedef struct __attribute__((packed)) {
	uint8_t hash_salt[HASHLEN];
	uint8_t len_exp[KEY_SLOT_EXP_MAX][4];
	uint8_t key_mask[HASHLEN];
} Key_slot;

typedef struct __attribute__((packed)) {
	bool key_slot_is_used[KEY_SLOT_COUNT];
	uint8_t all_key_mask[KEY_SLOT_COUNT][HASHLEN];
	uint32_t payload_offset;
	uint32_t header_size;
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
	
	numbers[0] = x + (rand1 % x);
	numbers[1] = x - (rand1 % x);
	numbers[2] = x + (rand1 % x);
	numbers[3] = x - (rand1 % x);
	
}


void write_or_read_mem_count_from_len_exp(Key_slot * key_slot, const uint8_t hash[HASHLEN], uint_fast8_t len_exp_index, uint64_t * mem_size, bool is_write) {
//	print("read:", (uint32_t) *key_slot->len_exp[len_exp_index]); TODO
//	print_hex_array(hash, HASHLEN);
	uint8_t plain_text[4];
	if (is_write) {
//		uint64_t mem_size_write = (uint64_t)*mem_size >> len_exp_index;
		uint64_t mem_size_write = (uint64_t)((double)*mem_size / exp((double) len_exp_index));
		generate_random_numbers(mem_size_write, plain_text);
		xor_with_len(sizeof(SPECK_TYPE) * 2, hash + sizeof(SPECK_TYPE) * SPECK_KEY_LEN, plain_text, plain_text);
		speck_encrypt_combined((const uint16_t *) plain_text, (uint16_t *) key_slot->len_exp[len_exp_index],
									  (const uint16_t *) hash);
		
		// hash has uint8_t[8] len, plain_text and cipher text has uint8_t[4]

	} else {
		speck_decrypt_combined((const uint16_t *) key_slot->len_exp[len_exp_index], (uint16_t *) plain_text,
									  (const uint16_t *) hash);
		xor_with_len(sizeof(SPECK_TYPE) * 2, hash + sizeof(SPECK_TYPE) * SPECK_KEY_LEN, plain_text, plain_text);
		*mem_size = plain_text[0] + plain_text[1] + plain_text[2] + plain_text[3];
		*mem_size = (uint64_t)(exp((double) len_exp_index) * (double)*mem_size / (double)4);
//		*mem_size = (uint64_t)len_exp_index << len_exp_index;
	}
//	print("write_or_read_mem_count_from_len_exp", (uint32_t) *plain_text, "enc text:", *mem_size, "with key:", (uint32_t) *hash);
}


void argon2id_hash_calc(Key_slot * key_slot, uint32_t m_cost, const void * pwd, uint_fast8_t len_exp_index, uint8_t hash[HASHLEN]) {
	if (m_cost == 0){
		return;
	}
	if (m_cost < BASE_MEM_COST) {
		m_cost = BASE_MEM_COST;
	}
	argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, key_slot->hash_salt,
							sizeof(key_slot->hash_salt) + sizeof(key_slot->len_exp[len_exp_index]) * len_exp_index, hash, HASHLEN);
}


bool calc_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint64_t max_mem_size) {
	uint8_t new_hash[HASHLEN];
//	print("calc_key_one_step:", len_exp_index, max_mem_size);
	uint64_t required_mem_size;
	write_or_read_mem_count_from_len_exp(key_slot, password_hash, len_exp_index, &required_mem_size, false);
	if (required_mem_size > max_mem_size) {
		return false;
	}
	argon2id_hash_calc(key_slot, required_mem_size, password_hash, len_exp_index, new_hash);
	memcpy(password_hash, new_hash, HASHLEN);
	return true;
}

void write_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint64_t target_mem_size) {
//	print("write_key_one_step:", len_exp_index, target_mem_size);
	uint8_t new_pwd[HASHLEN];
	write_or_read_mem_count_from_len_exp(key_slot, password_hash, len_exp_index, &target_mem_size, true);
	argon2id_hash_calc(key_slot, target_mem_size, password_hash, len_exp_index, new_pwd);
	memcpy(password_hash, new_pwd, HASHLEN);
}

double hash_firstpass_and_benchmark(Key_slot * key_slot, uint8_t inited_key[HASHLEN], uint8_t password_hash[HASHLEN]) {
	clock_t start_time, stop_time;
	start_time = clock();
	argon2id_hash_calc(key_slot, BASE_MEM_COST * 4, inited_key, 0, password_hash);
	stop_time = clock();
	return (double) (stop_time - start_time) / (CLOCKS_PER_SEC);
}


bool argon2id_iter_hash_one_slot(Key_slot * key_slot, const uint8_t password_hash[HASHLEN], uint8_t new_hash[HASHLEN], uint64_t max_mem_size, bool is_new_pw) {
	memcpy(new_hash, password_hash, HASHLEN);
	bool is_memory_enough = true;
	for (int_fast8_t i = 0; i < KEY_SLOT_EXP_MAX; i++) {
		if (is_memory_enough) {
			is_memory_enough = calc_key_one_step(key_slot, i, new_hash, max_mem_size);
		}
		if (!is_memory_enough) {
			if (!is_new_pw) {
				return false;
			}
			write_key_one_step(key_slot, i, new_hash, 0);
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

void get_metadata_key_and_disk_key_from_master_key(const uint8_t master_key[HASHLEN], const uint8_t master_key_mask[HASHLEN], uint8_t metadata_key[HASHLEN], uint8_t
disk_key[HASHLEN]) {
	uint8_t inter_key[HASHLEN];
	memcpy(inter_key, master_key, HASHLEN);
	for (int i = 0; i < HASHLEN; i++) {
		inter_key[i] = master_key[i] ^ master_key_mask[i];
	}
	if (metadata_key != NULL) {
		argon2id_hash_raw(1, BASE_MEM_COST, PARALLELISM, master_key, HASHLEN, "the hash of metadata key", strlen("the hash of metadata key"), metadata_key, HASHLEN);
	}
	if (disk_key != NULL) {
		argon2id_hash_raw(1, BASE_MEM_COST, PARALLELISM, inter_key, HASHLEN, "the hash of disk key", strlen("the hash of disk key"), disk_key, HASHLEN);
	}
}

uint64_t calc_initial_pw_hash_and_iter_cnt(Data * self, uint8_t * inited_key, int target_slot, uint64_t max_mem_size, double time_limit, uint8_t
password_hash_all_slots[KEY_SLOT_COUNT][HASHLEN], uint8_t password_hash[HASHLEN]) {
	// password hash is password_hash_all_slots[KEY_SLOT_COUNT][HASHLEN] if target_slot == -1, else use password_hash[HASHLEN]
	double time_cost = 0;
//	print("mem-size", max_mem_size, "time-limit", time_limit);
	if (target_slot == -1) { // all slots
		// initial hash and benchmarking
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			Key_slot * key_slot = &self->keys[i];
			time_cost += hash_firstpass_and_benchmark(key_slot, inited_key, password_hash_all_slots[i]);
		}
		time_cost /= KEY_SLOT_COUNT;
	} else {
		time_cost = hash_firstpass_and_benchmark(&self->keys[target_slot], inited_key, password_hash);
	}
	
	if (time_limit > 0) {
		if (time_limit / time_cost * BASE_MEM_COST * 4 < (double) max_mem_size || max_mem_size == 0) {
			max_mem_size = (uint64_t) (time_limit / time_cost * BASE_MEM_COST * 4);
		}
	}
	return max_mem_size;
}

void operate_metadata_using_master_key(Metadata * metadata, const uint8_t master_key[HASHLEN], const uint8_t master_key_mask[HASHLEN], bool is_decrypt) {
	uint8_t metadata_key[HASHLEN];
	uint8_t iv[HASHLEN];
	
	get_metadata_key_and_disk_key_from_master_key(master_key, master_key_mask, metadata_key, NULL);
	sha256_digest_all(metadata_key, HASHLEN, iv);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, metadata_key, iv);
	
	if (is_decrypt) {
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) metadata, sizeof(Metadata));

	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) metadata, sizeof(Metadata));
	}
}

void initialize_unlock_header_and_master_key(Data * uninitialized_header, uint8_t master_key[32], const char * enc_type, uint32_t payload_offset) {
	fill_secure_random_bits((uint8_t *) uninitialized_header, sizeof(Data));
	
	operate_metadata_using_master_key(&uninitialized_header->metadata, master_key, uninitialized_header->master_key_mask, true);
	memset(uninitialized_header->metadata.key_slot_is_used, false, sizeof(uninitialized_header->metadata.key_slot_is_used));
	if (enc_type != NULL) {
		strcpy(uninitialized_header->metadata.enc_type, enc_type);
	} else {
		strcpy(uninitialized_header->metadata.enc_type, DEFAULT_DISK_ENC_MODE);
	}
	uninitialized_header->metadata.check_key_magic_number = CHECK_KEY_MAGIC_NUMBER;
	if (payload_offset == 0) {
		uninitialized_header->metadata.payload_offset = (512 - (sizeof(Data) % 512)) % 512;
	} else {
		uninitialized_header->metadata.payload_offset = payload_offset;
	}
}

void decrypt_header_using_master_key(Data * encrypted_header, uint8_t master_key[HASHLEN]){
	operate_metadata_using_master_key(&encrypted_header->metadata, master_key, encrypted_header->master_key_mask, true);
}

void finalize_header_using_master_key(Data * decrypted_header, uint8_t master_key[HASHLEN]) {
	operate_metadata_using_master_key(&decrypted_header->metadata, master_key, decrypted_header->master_key_mask, false);
}

void revoke_given_key_slot(Data * initialized_header, int target_slot) {
	fill_secure_random_bits(initialized_header->keys[target_slot].key_mask, HASHLEN);
}

void register_key_slot_as_used(Metadata * decrypted_metadata, Key_slot keys[KEY_SLOT_COUNT], int slot) {
	decrypted_metadata->key_slot_is_used[slot] = true;
	memcpy(decrypted_metadata->all_key_mask[slot], keys[slot].key_mask, HASHLEN);
}

int select_available_key_slot(const Metadata decrypted_metadata, Key_slot keys[KEY_SLOT_COUNT]) {
	int target_slot = -1;
	for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--) {
		if (decrypted_metadata.key_slot_is_used[i] == false) {
			target_slot = i;
		}
	}
	if (target_slot == -1) {
		for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--) {
			if (memcmp(keys[i].key_mask, decrypted_metadata.all_key_mask[i], HASHLEN) != 0) {
				target_slot = i;
			}
		}
	}
	return target_slot;
}
