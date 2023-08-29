#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

#define KEY_SLOT_COUNT 6
#define KEY_SLOT_EXP_MAX 16
#define HASHLEN 32
#define BASE_MEM_COST 128
#define PARALLELISM 1
#define SPECK_ROUNDS 12
#define DEFAULT_ENC_TARGET_TIME 0.75

#include "print.c"
#include "library/Argon2/argon2.h"
#include "library/speck/speck.h"

#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif


int random_fd;

typedef struct __attribute__((packed)) {
	uint8_t hash_salt[HASHLEN];
	uint8_t len_exp[KEY_SLOT_EXP_MAX][4];
	uint8_t key_mask[HASHLEN];
} Key_slot;

typedef struct __attribute__((packed)) {
	uint8_t enc_type[32];
	bool key_slot_usage[KEY_SLOT_COUNT];
	time_t raw_creat_time;
	uint32_t payload_offset;
} Metadata;

typedef struct __attribute__((packed)) {
	__attribute__((unused)) uint8_t head[16]; // '\xe8' '\xb4' '\xb4' '\xe8' '\xb4' '\xb4' 'l' 'e' 'v' 'e' 'l' '-' '1' '2' '8' '!'
	char master_key_mask[32];
	Key_slot keys[KEY_SLOT_COUNT];
	Metadata metadata;
} Data;

#pragma once

static uint64_t rdtsc() {
#if defined(__amd64__) || defined(__x86_64__)
	uint64_t rax, rdx;
	__asm__ __volatile__("rdtsc" : "=a"(rax), "=d"(rdx) : :);
	return (rdx << 32) | rax;
#elif defined(__i386__) || defined(__i386) || defined(__X86__)
	uint64_t rax;
	__asm__ __volatile__("rdtsc" : "=A"(rax) : :);
	return rax;
#else
	return NULL;
#endif
}

void print_hex_array(const uint8_t * arr, size_t length) {
	for (size_t i = 0; i < length; ++i) {
		printf("%02x ", arr[i]);
	}
	printf("\n");
}

void fill_secure_random_bits(void * address, size_t size) {
	ssize_t read_size = read(random_fd, address, size);
	if (read_size != (ssize_t) size) {
		print("IO error while reading /dev/urandom.");
		*((volatile int *) NULL) = 0; // generate core dump
	}
}

void generate_random_numbers(uint8_t x, uint8_t numbers[4]) {
	if (x == 0) {
		memset(numbers, 0, 4);
		return;
	}
	uint8_t rand1 = random();
	uint8_t rand2 = random();
	uint8_t rand3 = random();
	numbers[0] = x + (rand1 % x);
	numbers[1] = x - (rand1 % x);
	numbers[2] = x + (rand1 % x);
	numbers[3] = x - (rand1 % x);
	numbers[0] + rand2 + rand3;
	numbers[1] + rand2 - rand3;
	numbers[2] - rand2 + rand3;
	numbers[3] - rand2 - rand3;
}

void calc_cnt(Key_slot * key_slot, const uint8_t hash[HASHLEN], uint_fast8_t len_exp_index, uint64_t * mem_size, bool is_write) {
	uint8_t plain_text[4];
	if (is_write) {
		*mem_size >>= len_exp_index;
		generate_random_numbers(*mem_size, plain_text);
		*mem_size <<= len_exp_index;
		speck_encrypt_combined((const uint16_t *) plain_text, (uint16_t *) key_slot->len_exp[len_exp_index],
									  (const uint16_t *) hash);
		print("calc_int_write", (uint32_t) *plain_text, "enc text:", (uint32_t) *key_slot->len_exp[len_exp_index], "with key:", (uint32_t) *hash);
	} else {
		speck_decrypt_combined((uint16_t *) key_slot->len_exp[len_exp_index], (uint16_t *) plain_text,
									  (const uint16_t *) hash);
		*mem_size = plain_text[0] + plain_text[1] + plain_text[2] + plain_text[3];
		*mem_size = ((*mem_size / 4) << len_exp_index);
		print("calc_int_read", (uint32_t) *plain_text, "enc text:", (uint32_t) *key_slot->len_exp[len_exp_index], "with key:", (uint32_t) *hash);
	}
}


void argon2id_calc(Key_slot * key_slot, uint32_t m_cost, const void * pwd, uint_fast8_t len_exp_index, void * hash) {
	if (m_cost < BASE_MEM_COST) {
		m_cost = BASE_MEM_COST;
	}
	argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, key_slot->hash_salt,
							sizeof(key_slot->hash_salt) + sizeof(key_slot->len_exp[len_exp_index]) * len_exp_index, hash, HASHLEN);
}


bool calc_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint64_t max_mem_size) {
	uint8_t new_hash[HASHLEN];
	print("calc_key_one_step:", len_exp_index, max_mem_size);
	uint64_t required_mem_size;
	calc_cnt(key_slot, password_hash, len_exp_index, &required_mem_size, false);
	if (required_mem_size > max_mem_size) {
		return false;
	}
	argon2id_calc(key_slot, required_mem_size, password_hash, len_exp_index, new_hash);
	memcpy(password_hash, new_hash, HASHLEN);
	return true;
}

void write_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t pwd[HASHLEN], uint64_t target_mem_size) {
	print("write_key_one_step:", len_exp_index, target_mem_size);
	uint8_t new_pwd[HASHLEN];
	calc_cnt(key_slot, pwd, len_exp_index, &target_mem_size, true);
	argon2id_calc(key_slot, target_mem_size, pwd, len_exp_index, new_pwd);
	memcpy(pwd, new_pwd, HASHLEN);
}

double hash_firstpass_and_benchmark(Key_slot * key_slot, uint8_t inited_key[HASHLEN], uint8_t password_hash[HASHLEN]) {
	clock_t start_time, stop_time;
	start_time = clock();
	argon2id_calc(key_slot, BASE_MEM_COST * 4, inited_key, 0, password_hash);
	stop_time = clock();
	return (double) (stop_time - start_time) / (CLOCKS_PER_SEC);
}


bool argon2id_calc_key_one_slot(Key_slot * key_slot, const uint8_t password_hash[HASHLEN], uint8_t new_hash[HASHLEN], uint64_t max_mem_size, bool is_new_pw) {
	memcpy(new_hash, password_hash, HASHLEN);
	bool is_memory_enough = true;
	for (int_fast8_t i; i < KEY_SLOT_EXP_MAX; i++) {
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
	uint8_t new_hash[HASHLEN];
	if (argon2id_calc_key_one_slot(key_slot, password_hash, new_hash, max_mem_size, false) == false) {
		return false;
	}
	print("get hashed password:");
	print_hex_array(new_hash, HASHLEN);
	for (int i = 0; i < HASHLEN; i++) {
		master_key[i] = new_hash[i] ^ key_slot->key_mask[i];
	}
	
	return true;
}

void set_master_key_to_slot(Key_slot * key_slot, const uint8_t password_hash[HASHLEN], uint64_t target_mem_size, const uint8_t master_key[HASHLEN]) {
	uint8_t new_hash[HASHLEN];
	argon2id_calc_key_one_slot(key_slot, password_hash, new_hash, target_mem_size, true);
	print("set hashed password:");
	print_hex_array(new_hash, HASHLEN);
	for (int i = 0; i < HASHLEN; i++) {
		key_slot->key_mask[i] = new_hash[i] ^ master_key[i];
	}
}


int enclib_main() {
//    int fd = open("/dev/urandom", O_RDONLY);
//    if (fd == -1) {
//        return 1;
//    }
	
	Data * my_data = malloc(sizeof(Data));
	
	// test case
	print("new pw:\n");
	void * password = calloc(HASHLEN, 1);
	strcpy(password, "hello world!");
	set_master_key_to_slot(&my_data->keys[0], password, 4000, (uint8_t *) "a master key example. ");
	
	password = calloc(HASHLEN, 1);
	uint8_t * masterkey = malloc(HASHLEN);
	strcpy(password, "hello world!");
	if (!get_master_key_from_slot(&my_data->keys[0], password, 20000, masterkey)) { print_error("wrong master key"); }
	print((char *) masterkey);
}
