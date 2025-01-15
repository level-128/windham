//
// Created by level-128 on 8/31/23.
//

#include <memory.h>
#include <malloc.h>
#include "assert.h"
#include "../library_intrnlsrc/enclib.c"
//
//
// void test_set_get_master_key() {
// 	Data my_data;
// 	fill_secure_random_bits((uint8_t *) &my_data, sizeof(my_data));
//
// 	uint8_t masterkey[HASHLEN];
// 	uint8_t password_set[KEY_SLOT_COUNT][HASHLEN];
// 	int slot_seq[KEY_SLOT_COUNT + 1] = {0, -1};
//
//
// 	fill_secure_random_bits((uint8_t *) password_set, HASHLEN);
// 	for (int i = 1; i < KEY_SLOT_COUNT; i++) {
// 		memcpy(password_set[i], password_set[0], HASHLEN);
// 	}
//
// 	fill_secure_random_bits(password_set[0], sizeof(password_set[0]));
// 	set_master_key_to_slot(&my_data.keyslots[0], (const uint8_t *) password_set, 150000000000, 2, (uint8_t *) "a master key example.          ");
//
// 	fill_secure_random_bits(masterkey, HASHLEN);
//
// 	int unlocked_slot = read_key_from_all_slots(my_data.keyslots, password_set, slot_seq, 200000000000, 4);
// 	xor_with_len(HASHLEN, password_set[unlocked_slot], my_data.keyslots[unlocked_slot].key_mask, masterkey);
// 	assert(unlocked_slot == 0);
// 	assert(strcmp((char *) masterkey, "a master key example.          ") == 0);
//
// };
//
// void test_metadata() {
// 	Data my_data;
//
// 	uint8_t masterkey[HASHLEN] = {'h', 'e', 'l', 'l', 'o'};
// 	strcpy(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE);
// 	fill_secure_random_bits((uint8_t *) &my_data, sizeof(Data));
// 	my_data.metadata.check_key_magic_number = CHECK_KEY_MAGIC_NUMBER;
// 	assert(lock_or_unlock_metadata_using_master_key(&my_data, masterkey));
//
// 	assert(lock_or_unlock_metadata_using_master_key(&my_data, masterkey));
// }
//
// void test_argon2b3() {
// 	const size_t m_cost = 1024;
//
// 	uint8_t pwd[HASHLEN];
// 	uint8_t salt[HASHLEN];
// 	uint8_t hash[HASHLEN];
// 	uint8_t hash_res[HASHLEN];
//
// 	fill_secure_random_bits(pwd, HASHLEN);
// 	fill_secure_random_bits(salt, HASHLEN);
//
//
// 	argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, salt,
// 	                  HASHLEN, hash, HASHLEN);
// 	argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, salt,
// 	                  HASHLEN, hash_res, HASHLEN);
// 	assert(memcmp(hash, hash_res, HASHLEN) == 0);
// };

void test_enclib() {
	// test_argon2b3();
	// test_set_get_master_key();
	// test_metadata();
}
