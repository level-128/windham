#pragma once

#include "windham_const.h"

#include "srclib.c"
#include "argon2B3.h"
#include "aes.h"
#include "sha256.h"


#if KEY_SLOT_EXP_MAX % 4 != 0
#error "KEY_SLOT_EXP_MAX must devideable by 4, ensuring Key_slot is AES blocksize alligned."
#endif


/**
 * @enum ActionResult
 * Enumeration of possible result codes returned by an action step.
 * @note These values are negative to indicate errors.
 */
typedef enum {
	NMOBJ_STEP_OK = -1,
	NMOBJ_STEP_CONTINUE = -2,
	NMOBJ_STEP_ERR_NOMEM = -3,
	NMOBJ_STEP_ERR_TIMEOUT = -4,
	NMOBJ_STEP_ERR_END = -5
} ENUM_STEP_STAT;

typedef enum{
	EMOBJ_SLOT_AVALIABLE,
	EMOBJ_SLOT_AVALIABLE_REVOKE_ONLY,
	EMOBJ_SLOT_NO_SLOT,
} ENUM_select_available_key_slot;


// approx val of \lim_{n -> \inf} ( \sum_{i = 0}^{n} e^i )^{-1} * e^(n + 1)
const double exp_index_diff = 1.64905;

const unsigned int exp_PDF_p_bound = 66; // p=0.05

// floor(exp(i))
const uint64_t exp_val[] = {1, 3, 7, 20, 55, 148, 403, 1097, 2981, 8103, 22026, 59874, 162755, 442413, 1202604, 3269017, 8886111, 24154953, 65659969, 178482301, 485165195};

const uint8_t head[16] = {'\xe8', '\xb4', '\xb4', '\xe8', '\xb4', '\xb4', 'l', 'e', 'v', 'e', 'l', '-', '1', '2', '8', '!'};

const uint8_t head_converting[16] = {'E', 'N', 'C', 'I', 'N', 'G', 'l', 'e', 'v', 'e', 'l', '-', '1', '2', '8', '!'};

// data
#ifndef INCL_ENCLIB
#define INCL_ENCLIB

void fill_secure_random_bits(uint8_t * address, size_t size) {
	size_t read_size = fread(address, 1, size, random_fd);
	if (read_size != size) {
		print_error(_("IO error while reading from the random generator."));
	}
}

extern inline bool is_header_suspended(const Data encrypted_header) {
	return memcmp(encrypted_header.head, head, 16) == 0;
}

static int argon2id_hash_calc(const uint8_t pwd[HASHLEN], uint_fast8_t len_exp_index, const uint8_t salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], uint8_t hash[HASHLEN],
                              uint_fast32_t m_cost) {
	if (m_cost < BASE_MEM_COST) {
		m_cost = BASE_MEM_COST;
	}
	int ret = argon2id_hash_raw(1, m_cost, PARALLELISM, pwd, HASHLEN, salt,
	                            HASHLEN + len_exp_index * sizeof(uint8_t) * 4, hash, HASHLEN);
	if (ret == ARGON2_MEMORY_ALLOCATION_ERROR) {
		return NMOBJ_STEP_ERR_NOMEM;
	} else if (ret != ARGON2_OK) {
		exit(ret);
	}
	print("argon2id_hash_calc res:", hash[0], hash[1], hash[2], hash[3], "pwd: ", pwd[0], pwd[1], pwd[2], pwd[3]);
	print("len_exp_index:", len_exp_index, "mcost:", m_cost, "salt:", salt[0], salt[1], salt[2], salt[3]);
	return 0;
}

/**
 * @see write_to_exp
 */
static uint64_t write_mem_count_from_len_exp_and_update_salt(Key_slot * key_slot, const uint8_t hash[HASHLEN], uint_fast8_t len_exp_index,
                                                             uint8_t salt[], uint8_t new_mem[4]) {
	xor_with_len(sizeof(uint8_t) * 4, hash, new_mem, key_slot->len_exp[len_exp_index]);
	
	memcpy(&salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], key_slot->len_exp[len_exp_index], sizeof(uint8_t) * 4);
	// hash has uint8_t[8] len, plain_text and cipher text has uint8_t[4]
	print("write mem count:", new_mem[0], new_mem[1], new_mem[2], "for len exp:", len_exp_index, "with hash:", hash[0], hash[1], hash[2]);
	return 0;
}

/**
 * @see read_key_one_step
 */
static uint64_t read_mem_count_from_len_exp_and_update_salt(Key_slot * key_slot, const uint8_t hash[HASHLEN], uint_fast8_t len_exp_index, uint8_t salt[]) {
	uint8_t plain_text[4];
	memcpy(&salt[HASHLEN + len_exp_index * sizeof(uint8_t) * 4], key_slot->len_exp[len_exp_index], sizeof(uint8_t) * 4);
	
	xor_with_len(sizeof(uint8_t) * 4, hash, key_slot->len_exp[len_exp_index], plain_text);
	
	uint64_t mem_size = (plain_text[0] + plain_text[1] + plain_text[2] + plain_text[3]) / 4;
	print("read mem count:", mem_size, "for len exp:", len_exp_index, "with hash:", hash[0], hash[1], hash[2]);
	return mem_size * exp_val[len_exp_index];
}

/**
 * @brief Reads key in one step and updates the password hash.
 *
 * This function and function read_mem_count_from_len_exp_and_update_salt reads a key in one step by performing the following operations:
 * 1. Reads the memory count from the len_exp field of the key slot and updates the salt.
 * 2. Checks if the required memory size exceeds the maximum memory size. If it does, returns an error code indicating no memory.
 * 3. Calculates the new password hash using the argon2id_hash_calc function. If the calculation fails due to insufficient memory, returns an error code indicating no memory.
 * 4. Copies the new password hash to the password_hash array.
 * 5. Returns an error code indicating the result of the key reading operation.
 *
 * @param key_slot The key slot containing the key details.
 * @param len_exp_index The index of the len_exp field in the key slot.
 * @param password_hash The current password hash.
 * @param salt The salt used for key operations.
 * @param max_mem_size The maximum memory size allowed for key operations.
 * @param required_mem_size A pointer to the variable storing the required memory size.
 * @return An ENUM_STEP_STAT enum value indicating the result of the key reading operation. Possible values: NMOBJ_STEP_ERR_NOMEM, NMOBJ_STEP_OK, NMOBJ_STEP_CONTINUE.
 *
 * @see Key_slot
 * @see read_mem_count_from_len_exp_and_update_salt
 * @see argon2id_hash_calc
 * @see NMOBJ_STEP_ERR_NOMEM
 * @see NMOBJ_STEP_OK
 * @see NMOBJ_STEP_CONTINUE
 */
static ENUM_STEP_STAT read_key_one_step(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint8_t salt[HASHLEN + KEY_SLOT_EXP_MAX * 4], uint64_t max_mem_size,
                             uint64_t * required_mem_size) {
	uint8_t new_pwd[HASHLEN];
	
	*required_mem_size = read_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt);
	if (*required_mem_size > max_mem_size) {
		return NMOBJ_STEP_ERR_NOMEM;
	}
	if (argon2id_hash_calc(password_hash, len_exp_index, salt, new_pwd, *required_mem_size) == NMOBJ_STEP_ERR_NOMEM) {
		return NMOBJ_STEP_ERR_NOMEM;
	}
	memcpy(password_hash, new_pwd, HASHLEN);
	return *required_mem_size == 0 ? NMOBJ_STEP_OK : NMOBJ_STEP_CONTINUE;
}

static void operate_key_slot_using_keyslot_key(Key_slot * keyslot, const uint8_t keyslot_key[32], const uint8_t master_key_mask[32], bool is_decrypt) {
	uint8_t temp_key[HASHLEN];
	
	xor_with_len(HASHLEN, keyslot_key, master_key_mask, temp_key);
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, temp_key, master_key_mask);
	
	if (is_decrypt) {
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) keyslot, sizeof(Key_slot));
	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) keyslot, sizeof(Key_slot));
	}
}

/**
 * @brief Writes data to the Key_slot structure based on the given parameters.
 *
 * This function calculates the target memory size based on the remaining time, exponential index difference, and time per KiB of memory. If the target memory size exceeds the maximum
 * memory size, it is capped to the maximum value. The target memory size is then divided by the exponential value corresponding to the given length exponential index (it will be restored
 * to the original size by multiplying with the exponential value in read_mem_count_from_len_exp_and_update_salt).
 *
 * If the target memory size is larger than the predefined PDF bound (p >= 0.05), random values are generated to fill a four-byte array. The values are sorted in ascending order and stored
 * in the new_mem array. The write_mem_count_from_len_exp_and_update_salt function is then called to write the memory count to the Key_slot structure and update the salt value. If the result
 * of the read_key_one_step function is NMOBJ_STEP_CONTINUE, the length exponential index is incremented by one.
 *
 * The new_mem array is cleared and the write_mem_count_from_len_exp_and_update_salt function is called again with an array of zeros. The argon2id_hash_calc function is used to calculate
 * a new password hash based on the updated length exponential index and salt values. If the result of the argon2id_hash_calc function is NMOBJ_STEP_ERR_NOMEM, the program exits with
 * an error code. Otherwise, the new password hash is copied to the password_hash array.
 *
 * @param key_slot A pointer to the Key_slot structure.
 * @param len_exp_index The length exponential index.
 * @param password_hash The password hash.
 * @param salt The salt value.
 * @param time_left The remaining time.
 * @param time_per_KiB_mem The time per KiB of memory.
 * @param max_mem_size The maximum memory size.
 * @return 0 if the write operation is successful.
 */
static void write_to_exp(Key_slot * key_slot, uint_fast8_t len_exp_index, uint8_t password_hash[HASHLEN], uint8_t salt[112], double time_left, double time_per_KiB_mem, uint64_t max_mem_size) {
//	print("write_to_exp:", len_exp_index, target_mem_size);
	uint8_t new_mem[4];
	if (time_left > 0) {
		uint64_t _;
		size_t target_mem_size = ((size_t) (time_left * exp_index_diff / time_per_KiB_mem));
		if (target_mem_size > max_mem_size) {
			target_mem_size = max_mem_size;
		}
		target_mem_size = target_mem_size / exp_val[len_exp_index];
		
		print("target_mem_size:", target_mem_size);
		if (target_mem_size > exp_PDF_p_bound) { //larger than p=0.05
			RAND:;
			int64_t a = (int64_t) (random() % (target_mem_size * 4));
			int64_t b = (int64_t) (random() % (target_mem_size * 4));
			int64_t c = (int64_t) (random() % (target_mem_size * 4));
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
			write_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, new_mem);
			if (read_key_one_step(key_slot, len_exp_index, password_hash, salt, UINT64_MAX, &_) == NMOBJ_STEP_CONTINUE) {
				len_exp_index++;
			}
		}
	}
	
	memset(new_mem, 0, sizeof(new_mem));
	uint8_t new_pwd[HASHLEN];
	write_mem_count_from_len_exp_and_update_salt(key_slot, password_hash, len_exp_index, salt, new_mem);
	if (argon2id_hash_calc(password_hash, len_exp_index, salt, new_pwd, 0) == NMOBJ_STEP_ERR_NOMEM) {
		exit(1); // not possible. since m_count is BASE_MEM_COST.
	}
	memcpy(password_hash, new_pwd, HASHLEN);
}

/**
 * @brief Writes the key to one slot in the Key_slot structure.
 *
 * This function writes the key to one slot in the Key_slot structure based on the target time:
 * It calculates the required memory size and iterates through the slot expansion indexes.
 *
 * For each index, it checks the time used and compares it with the target time.
 * If the time used exceeds the target time divided by the exponential index difference,
 * it calls the write_to_exp function and breaks the loop.
 *
 * Otherwise, it calls the read_key_one_step function to read the key one step at a time,
 * updating the required memory size. If the read step returns NMOBJ_STEP_OK (0),
 * indicating that the read memory count is 0, it fills the key's length expansion with secure random bits.
 * If the read step returns NMOBJ_STEP_ERR_NOMEM (-3), indicating a memory allocation error,
 * it calls the write_to_exp function to end the writing process and returns NMOBJ_STEP_ERR_NOMEM.
 *
 * @param key_slot      The Key_slot structure to write the key.
 * @param hash          The hash value to be written.
 * @param max_mem_size  The maximum memory size allowed.
 * @param target_time   The target time for writing the key.
 * @return              NMOBJ_STEP_OK if successful, NMOBJ_STEP_ERR_NOMEM if memory allocation error occurs.
 */
static ENUM_STEP_STAT write_key_to_one_slot(Key_slot * key_slot, uint8_t hash[HASHLEN], uint64_t max_mem_size, double target_time) {
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
		if (res == NMOBJ_STEP_OK) { // the read memory count is 0
			fill_secure_random_bits(key_slot->len_exp[i], sizeof(key_slot->len_exp[i]));
			goto READ;
		} else if (res == NMOBJ_STEP_ERR_NOMEM) {
			write_to_exp(key_slot, i, hash, salt, 0, 0, UINT64_MAX); // ending
			return NMOBJ_STEP_ERR_NOMEM;
		}
	}
	return NMOBJ_STEP_OK;
}

/**
 * @brief Reads the key from all slots and performs one step of key calculation.
 *
 * This function reads the key from all slots in the given sequence and performs one step of key calculation using the read_key_one_step function.
 * The calculation continues until the target time is reached or the maximum number of exponential steps is reached for all slots.
 *
 * @param data$keyslots The array of key slot data.
 * @param inited_keys Array of initialized keys for each slot.
 * @param slot_seq The sequence of slots to calculate the key.
 * @param max_mem_size The maximum memory size for key calculation.
 * @param target_time The target time in seconds to perform the key calculation.
 *
 * @note This function assumes that the Key_slot structure and other definitions used in this code are defined in the same file.
 *
 * @return Returns NMOBJ_STEP_ERR_TIMEOUT if the target time is reached, NMOBJ_STEP_ERR_NOMEM if there is not enough memory,
 *         NMOBJ_STEP_OK if the key is successfully calculated for a slot, NMOBJ_STEP_ERR_END if all slots have reached the maximum number of exponential steps.
 */
int read_key_from_all_slots(Key_slot data$keyslots[KEY_SLOT_COUNT], uint8_t inited_keys[KEY_SLOT_COUNT][HASHLEN], const int slot_seq[KEY_SLOT_COUNT + 1], uint64_t max_mem_size, double target_time) {
	// initialize salt array
	uint8_t salts[KEY_SLOT_COUNT][HASHLEN + KEY_SLOT_EXP_MAX * 4];
	for (int i = 0; slot_seq[i] != -1; i++) {
		memcpy(salts[slot_seq[i]], data$keyslots[slot_seq[i]].hash_salt, HASHLEN);
	}
	
	int is_continue_calc_s[KEY_SLOT_COUNT];
	memset(is_continue_calc_s, NMOBJ_STEP_CONTINUE, sizeof(int) * KEY_SLOT_COUNT);
	
	clock_t start_time = clock();
	target_time = slot_seq[1] == -1 ? target_time : target_time * KEY_SLOT_COUNT;
	
	print_ptr_poz(-1, 0, KEY_SLOT_COUNT);
	
	for (int i = 0; i < KEY_SLOT_EXP_MAX; i++) {
		for (int j = 0; slot_seq[j] != -1; j++) {
			int slot = slot_seq[j];
			if (((double) clock() - (double) start_time) / CLOCKS_PER_SEC > target_time) {
				return NMOBJ_STEP_ERR_TIMEOUT;
			}
			
			if (is_continue_calc_s[slot] != NMOBJ_STEP_ERR_NOMEM) {
				print_ptr_poz(slot, i + 1, KEY_SLOT_COUNT); // print current slot and progress
				uint64_t _;
				is_continue_calc_s[slot] = read_key_one_step(&data$keyslots[slot], i, inited_keys[slot], salts[slot], max_mem_size, &_);
				if (is_continue_calc_s[slot] == NMOBJ_STEP_ERR_NOMEM) {
					print_ptr_poz(slot, -1, KEY_SLOT_COUNT);
				} else if (is_continue_calc_s[slot] == NMOBJ_STEP_OK) {
					print_ptr_poz(slot, 0, KEY_SLOT_COUNT);
					return slot;
				}
			}
		}
	}
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		if (is_continue_calc_s[i] == NMOBJ_STEP_CONTINUE) {
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
	if (write_key_to_one_slot(key_slot, new_hash, target_mem_size, target_time) == NMOBJ_STEP_ERR_NOMEM) {
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
		AES_CBC_decrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(EncMetadata));
		return data->metadata.check_key_magic_number == CHECK_KEY_MAGIC_NUMBER;
	} else {
		AES_CBC_encrypt_buffer(&ctx, (uint8_t *) &data->metadata, sizeof(EncMetadata));
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
                                                        const uint8_t data$master_key_mask[HASHLEN], bool is_decrypt) {
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		operate_key_slot_using_keyslot_key(&data$keyslots[i], data$metadata$keyslot_key[i], data$master_key_mask, is_decrypt);
	}
}

void operate_all_keyslots_using_inited_key(Key_slot data$keyslots[KEY_SLOT_COUNT], const uint8_t inited_key[HASHLEN], const uint8_t data$master_key_mask[HASHLEN], const uint8_t data$uuid_and_salt[16],
                                           bool is_decrypt) {
	uint8_t keyslot_key[HASHLEN];
	get_keyslot_key_from_inited_key(inited_key, data$uuid_and_salt, keyslot_key);
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
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

void assign_new_header_iv(Data * unlocked_header) {
	fill_secure_random_bits(unlocked_header->head, sizeof(unlocked_header->head));
	fill_secure_random_bits(unlocked_header->master_key_mask, sizeof(unlocked_header->master_key_mask));
	fill_secure_random_bits(unlocked_header->AES_align, sizeof(unlocked_header->AES_align));
}

void tag_header_as_converting(Data * unlocked_header, uint64_t section_size){
	unlocked_header->metadata.section_size = (uint32_t) section_size;
	memcpy(unlocked_header->head, head_converting, sizeof(unlocked_header->head));
}

void untag_header_as_converting(Data * header){
	fill_secure_random_bits(header->head, sizeof(header->head));
}

void revoke_given_key_slot(Data * initialized_header, int target_slot, bool is_tag_revoke) {
	fill_secure_random_bits(initialized_header->keyslots[target_slot].key_mask, HASHLEN);
	if (is_tag_revoke) {
		memset(initialized_header->metadata.all_key_mask[target_slot], 0, HASHLEN);
	}
}

void register_key_slot_as_used(Data * decrypted_header, uint8_t keyslot_key[HASHLEN], int slot) {
	decrypted_header->metadata.key_slot_is_used[slot] = true;
	memcpy(decrypted_header->metadata.all_key_mask[slot], decrypted_header->keyslots[slot].key_mask, HASHLEN);
	memcpy(decrypted_header->metadata.keyslot_key[slot], keyslot_key, HASHLEN);
}


/**
 * @brief Selects an available key slot based on the given encrypted metadata and target slot.
 *
 * This function selects an available key slot based on the provided encrypted metadata and target slot. It checks if the target slot is designated and available. If not, it randomly
 * selects an available slot. If no empty slot is available, it selects a revoked slot instead. If all slots are registered, it returns EMOBJ_SLOT_NO_SLOT.
 *
 * @param decrypted_metadata The decrypted metadata containing key slot information.
 * @param target_slot Pointer to the target slot variable. This parameter is modified inside the function.
 * @param data$keyslots An array of key slots.
 * @return ENUM_select_available_key_slot The selected key slot status.
 */
ENUM_select_available_key_slot select_available_key_slot(const EncMetadata decrypted_metadata, int * target_slot, Key_slot data$keyslots[KEY_SLOT_COUNT]) {
	if (*target_slot != -1) { // if target_slot is not -1, means the user has designated a key slot. check it's available or not.
		if (decrypted_metadata.key_slot_is_used[*target_slot] == false){
			return EMOBJ_SLOT_AVALIABLE;
		}
		if (memcmp(data$keyslots[*target_slot].key_mask, decrypted_metadata.all_key_mask[*target_slot], HASHLEN) != 0) {
			return EMOBJ_SLOT_AVALIABLE_REVOKE_ONLY;
		}
	}
	
	srand((unsigned) time(NULL));
	int arr[KEY_SLOT_COUNT];
	
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		arr[i] = i;
	}
	
	for (int i = KEY_SLOT_COUNT - 1; i > 0; i--) {
		int j = rand() % (i + 1);
		int temp = arr[i];
		arr[i] = arr[j];
		arr[j] = temp;
	}
	
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		if (decrypted_metadata.key_slot_is_used[arr[i]] == false) {
			*target_slot = arr[i];
			return EMOBJ_SLOT_AVALIABLE;
		}
	}
	for (int i = 0; i < KEY_SLOT_COUNT; i++) { // if no empty slots, return a revoked slot.
		if (memcmp(data$keyslots[arr[i]].key_mask, decrypted_metadata.all_key_mask[arr[i]], HASHLEN) != 0) {
			*target_slot = arr[i];
			return EMOBJ_SLOT_AVALIABLE_REVOKE_ONLY;
		}
	}
	return EMOBJ_SLOT_NO_SLOT;
}

/**
 * @brief Check master key and slots for revocation.
 *
 * This function checks the master key and key slots in the decrypted header
 * for revocation. If a key slot is revoked, the corresponding key mask and key
 * data are cleared.
 *
 * @param decrypted_header The decrypted header data.
 * @param revoked_untagged_slot Output array indicating the revocation status of each key slot.
 *                              A value of true indicates that the key slot is revoked and untagged.
 */
void check_master_key_and_slots_revoke(Data * decrypted_header, bool revoked_untagged_slot[KEY_SLOT_COUNT]) {
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

void suspend_encryption(Data * encrypted_header, const uint8_t master_key[HASHLEN]) {
	memcpy(encrypted_header->head, head, sizeof(head));
	uint8_t key[HASHLEN];
	
	get_metadata_key_or_disk_key_from_master_key(master_key, encrypted_header->master_key_mask, encrypted_header->uuid_and_salt, key);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
	AES_CBC_decrypt_buffer(&ctx, encrypted_header->metadata.disk_key_mask, (intptr_t) encrypted_header->metadata.keyslot_key - (intptr_t) encrypted_header->metadata.disk_key_mask);
	
	xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
}

void resume_encryption(Data * encrypted_header, const uint8_t master_key[HASHLEN]) {
	fill_secure_random_bits(encrypted_header->head, sizeof(encrypted_header->head));
	uint8_t key[HASHLEN];
	
	xor_with_len(HASHLEN, master_key, encrypted_header->metadata.disk_key_mask, encrypted_header->metadata.disk_key_mask);
	get_metadata_key_or_disk_key_from_master_key(master_key, encrypted_header->master_key_mask, encrypted_header->uuid_and_salt, key);
	
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, encrypted_header->master_key_mask);
	AES_CBC_encrypt_buffer(&ctx, encrypted_header->metadata.disk_key_mask, (intptr_t) encrypted_header->metadata.keyslot_key - (intptr_t) encrypted_header->metadata.disk_key_mask);
}

#endif // #ifndef INCL_ENCLIB