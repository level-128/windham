//
// Created by level-128 on 1/19/24.
//

#ifndef INCL_BKLIBKEY
#define INCL_BKLIBKEY

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <windham_const.h>
#include <termios.h>

#include "bksrclib.c"
#include <sha256.h>
#include <huffman.h>


#define MIN_KEY_CHAR 7

typedef struct {
	char * key_or_keyfile_location;
	uint32_t key_type;
} Key;

enum {
	EMOBJ_key_file_type_input,
	EMOBJ_key_file_type_input_systemd,
	EMOBJ_key_file_type_key,
	EMOBJ_key_file_type_file,
	EMOBJ_key_file_type_masterkey,
};


char * get_password_input() {
	struct termios oldt, newt;
	int size = 20;
	char * input = (char *) malloc(size * sizeof(char));
	char ch;
	int index = 0;
	
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	
	while (1) {
		ch = (char) getchar();
		
		if (ch == '\n') {
			break;
		}
		input[index++] = ch;
		
		if (index == size) {
			size += 20;
			input = (char *) realloc(input, size * sizeof(char)); // NOLINT(*-suspicious-realloc-usage)
		}
	}
	
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	
	input[index] = '\0';
	return input;
}

char * get_key_input_from_the_console(const char * device, bool is_new_key) {
	char * key, * check_key;
	printf(_("Password for %s:\n"), device);
	key = get_password_input();
	printf(_("\nAgain:\n"));
	check_key = get_password_input();
	if (strcmp(key, check_key) != 0) {
		print_error(_("Passwords do not match."));
	} else if (strlen(key) < MIN_KEY_CHAR && is_new_key) {
		print_error(_("the provided password is too short (%zu characters), which is not recommended. To bypass this restriction, use argument --key instead."), strlen(key));
	}
	free(check_key);
	return key;
}

char * get_key_input_from_the_console_systemd(const char * device) {
	int exec_ret_val;
	char * dup_stdout = NULL;
	char * exec_dir[] = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL};
	size_t dup_stdout_len;
	char password_prompt[strlen("password for ") + strlen(device) + strlen(":") + 1];
	sprintf(password_prompt, "password for %s:", device);
	
	if (exec_name("systemd-ask-password", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, password_prompt, NULL) == false) {
		if (errno == ENOENT) {
			print_error(_("\"systemd-ask-password\" is not available. Param \"--systemd-dialog\" only supports system with systemd as init."));
		} else {
			print_error(_("failed to call \"systemd-ask-password\"."));
		}
	} else if (exec_ret_val != 0) {
		print_error(_("Cannot get password from systemd service"));
	}
	dup_stdout[dup_stdout_len - 1] = '\x00';
	return dup_stdout;
}

uint8_t * read_key_file(const Key key, size_t * length) {
	char * filename = key.key_or_keyfile_location;
	
	FILE * file = fopen(filename, "rb");

	if (file == 0){
		print_error(_("Cannot open keyfile %s. Reason: %s"), filename, strerror(errno));
	}
	
	fseek(file, 0, SEEK_END);
	*length = ftell(file);
	fseek(file, 0, SEEK_SET);
	
	uint8_t * buffer = malloc(*length);
	
	fread(buffer, 1, *length, file);
	fclose(file);
	
	return buffer;
}

void hash_key_file(size_t length, uint8_t input_key[length], uint8_t inited_key[length]){
	sha256_digest_all(input_key, length < 1024 ? length : 1024, inited_key);
	if (length > 1024){
		uint8_t blake3_hash_result[length];
		blake3_hasher_long(blake3_hash_result, HASHLEN, &input_key[1024], length - 1024);
		xor_with_len(HASHLEN, inited_key, blake3_hash_result, inited_key);
	}
}

bool prepare_key(const Key key, uint8_t inited_key[HASHLEN], const char * device) {
	size_t key_size;
	char * input_key = NULL;
	
	switch (key.key_type) {
		case EMOBJ_key_file_type_masterkey:
			return false;
		case EMOBJ_key_file_type_input:
			input_key = get_key_input_from_the_console(device, true);
			key_size = strlen(input_key);
			sha256_digest_all(input_key, key_size, inited_key);
			break;
		case EMOBJ_key_file_type_input_systemd:
			input_key = get_key_input_from_the_console_systemd(device);
			key_size = strlen(input_key);
			sha256_digest_all(input_key, key_size, inited_key);
			break;
		case EMOBJ_key_file_type_file:
			input_key = (char *) read_key_file(key, &key_size);
			hash_key_file(key_size, (uint8_t *) input_key, inited_key);
			break;
		case EMOBJ_key_file_type_key:
			key_size = strlen(key.key_or_keyfile_location);
			sha256_digest_all(key.key_or_keyfile_location, key_size, inited_key);
	}
	bool result = get_is_high_entropy(key_size, (uint8_t*) input_key);
	free(input_key);
	return result;
}

char * interactive_ask_new_key_test_key = NULL;

void interactive_prepare_key(Key * new_key, const char * device) {
	char option;
	if (interactive_ask_new_key_test_key == NULL) {
		printf(_("Add a new key for %s: choose your key format \n(1) input key from console;\n(2) use a key file\nOption: \n"), device);
		
		struct termios oldt, newt;
		
		tcgetattr(STDIN_FILENO, &oldt);
		newt = oldt;
		newt.c_lflag &= ~(ICANON | ECHO);
		tcsetattr(STDIN_FILENO, TCSANOW, &newt);
		
		option = (char) getchar();
		
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		
		printf("\n");
	} else {
		option = '1';
	}
	if (option == '1') {
		if (interactive_ask_new_key_test_key == NULL) {
			new_key->key_type = EMOBJ_key_file_type_input;
			new_key->key_or_keyfile_location = NULL;
		} else {
			new_key->key_type = EMOBJ_key_file_type_key;
			new_key->key_or_keyfile_location = interactive_ask_new_key_test_key;
			interactive_ask_new_key_test_key = NULL;
		}
	} else if (option == '2') {
		char * file_location;
		size_t len;
		printf("Key file location:");
		getline(&file_location, &len, stdin);
		new_key->key_or_keyfile_location = file_location;
		new_key->key_type = EMOBJ_key_file_type_file;
	}
}

void get_slot_list_for_get_master_key(int slot_seq[KEY_SLOT_COUNT + 1], int target_slot) {
	if (target_slot == -1) {
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			slot_seq[i] = i;
		}
		srand((unsigned) time(NULL));
		
		for (int i = KEY_SLOT_COUNT - 1; i > 0; i--) {
			int j = rand() % (i + 1);
			swap(slot_seq[i], slot_seq[j]);
			slot_seq[KEY_SLOT_COUNT] = -1;
		}
	} else {
		slot_seq[0] = target_slot;
		slot_seq[1] = -1;
	}
}

/**
 * @brief Retrieves the master key for a given target slot.
 *
 * This function is used to retrieve the master key for a target slot. The master key is retrieved by operating
 * on all key slots using an initialized key obtained from the input key. The function checks the maximum
 * memory limit and adjusts it if necessary. It also randomizes the unlock sequence if the target slot is not
 * designated. If the key cannot be unlocked due to incorrect key, insufficient memory, or timeout, an error
 * message is printed. If the unlock is successful, the master key is XORed with the key mask of the unlocked slot
 * and stored in the provided master_key array.
 *
 * @param self The data structure containing the key slots and other metadata
 * @param master_key The array where the master key will be stored
 * @param key The input key or key file location
 * @param device The device identifier
 * @param target_slot The target slot for the master key, or -1 if the unlock sequence should be randomized
 * @param max_unlock_mem The maximum unlock memory limit
 * @param max_unlock_time The maximum unlock time limit
 *
 * @return The index of the unlocked slot, or an error code if the unlock was unsuccessful
 */
int get_master_key(Data self, uint8_t master_key[HASHLEN], const Key key, const char * device, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	if (key.key_type == EMOBJ_key_file_type_masterkey) { // uses master key
		return -1;
	}
	uint8_t inited_key[HASHLEN];
	uint8_t inited_keys[KEY_SLOT_COUNT][HASHLEN];
	prepare_key(key, inited_key, device);
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		memcpy(inited_keys[i], inited_key, HASHLEN);
	}
	
	operate_all_keyslots_using_inited_key(self.keyslots, inited_key, self.master_key_mask, self.uuid_and_salt, true);
	
	max_unlock_mem = check_target_mem(max_unlock_mem, false);
	
	int slot_seq[KEY_SLOT_COUNT + 1]; // sequence for unlock
	get_slot_list_for_get_master_key(slot_seq, target_slot); // randomize the unlock sequence, or if target slot is designated, use the target_slot instead.
	
	
	int unlocked_slot = read_key_from_all_slots(self.keyslots, inited_keys, slot_seq, max_unlock_mem, max_unlock_time);
	if (unlocked_slot >= 0) {
		xor_with_len(HASHLEN, inited_keys[unlocked_slot], self.keyslots[unlocked_slot].key_mask, master_key);
	} else if (unlocked_slot == NMOBJ_STEP_ERR_NOMEM) {
		print_error(_("Cannot unlock the target probably due to incorrect key.\n"
		              "\tIf you are certain that the key is indeed correct, because the memory limit has reached, try increasing the maximum memory limit "
		              "using --max-unlock-memory. If the operation cannot be completed due to insufficient system "
		              "memory, consider exporting the master key on a more computationally powerful device and then use the "
		              "master key to unlock the target."));
	} else if (unlocked_slot == NMOBJ_STEP_ERR_TIMEOUT) {
		print_error(_("Cannot unlock the target probably due to incorrect key.\n"
		              "\tIf you are certain that the key is indeed correct, because the time limit has reached, try increasing the maximum time limit "
		              "using --max-unlock-time."));
	} else if (unlocked_slot == NMOBJ_STEP_ERR_END) {
		print_error(_("Please read carefully: You should not be seeing this error message. The occurrence of this error message means that the parameters for the key "
		              "iteration function have grown to the maximum value by design. Unless your computer has tens of TBs of RAM and you have spent a considerable "
		              "amount of time computing (if you really did so, then this would imply that the key you just provided is incorrect, which would be a false alarm), "
		              "the appearance of this error message is abnormal. This may imply that: 1. There is a fatal flaw in the program, one that could directly compromise "
		              "both its own security and that of the encrypted device. You should immediately stop using this program and report it to the developers; 2. The "
		              "program has been tampered with by an attacker. As above, you should immediately stop using it. Redownload the program and verify its signature, "
		              "and also please destroy the hard drives encrypted with the tampered program; 3. You come from a distant future, and you are using computational "
		              "power that surpasses the era of the software. In any case, this also means that the software "
		              "can no longer provide adequate security for the era in which you exist. I am sorry to inform you of the above."));
	}
	return unlocked_slot;
}

/**
 * @brief Adds a key to a key slot in the provided decrypted_self data structure.
 *
 * This function adds a key to a key slot in the decrypted_self data structure. It prepares the key, selects an available key slot, checks if the key is already used in any slot, and
* sets the master key to the selected slot. If adding the key is successful, it registers the key slot as used and returns the target slot.
 *
 * @param decrypted_self Pointer to the decrypted_self data structure.
 * @param master_key The master key used for encryption.
 * @param key The key or keyfile location to be added.
 * @param device The device name.
 * @param target_slot The target slot to add the key.
 * @param max_unlock_mem The maximum unlock memory.
 * @param max_unlock_time The maximum unlock time.
 * @param is_no_detect_entropy Do not attempt to add the key with decreased cost when the key has high entropy.
 * @return The target slot.
 */
int add_key_to_keyslot(Data * decrypted_self, const uint8_t master_key[32], const Key key, const char * device, int target_slot, uint64_t max_unlock_mem, double max_unlock_time, bool is_no_detect_entropy) {
	uint8_t inited_key[HASHLEN];
	uint8_t keyslot_key[HASHLEN];
	
	bool is_high_entropy_key = prepare_key(key, inited_key, device);
	
	switch (select_available_key_slot(decrypted_self->metadata, &target_slot, decrypted_self->keyslots)) {
		case EMOBJ_SLOT_AVALIABLE:
			break;
		case EMOBJ_SLOT_AVALIABLE_REVOKE_ONLY:
			print_warning(_("No unused slots, select a revoked slot instead."));
			break;
		case EMOBJ_SLOT_NO_SLOT:
			print_error(_("All key slots are full. Remove or revoke one or more keys to add a new key."));
	}
	
	get_keyslot_key_from_inited_key(inited_key, decrypted_self->uuid_and_salt, keyslot_key);
	
	// check keyslots revoked without auth.
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		if (memcmp(decrypted_self->metadata.keyslot_key[i], keyslot_key, HASHLEN) == 0) {
			print_error(_("The given key is used at slot %i"), i);
		}
	}
	
	if (is_high_entropy_key && !is_no_detect_entropy){
		max_unlock_mem = 0;
		printf(_("High entropy key detected, adding the key to the keyslot with decreased cost to increase unlock speed. to disable this feature, use \"--no-detect-entropy\"\n"));
	} else {
		max_unlock_mem = check_target_mem(max_unlock_mem, true);
	}
	
	set_master_key_to_slot(&decrypted_self->keyslots[target_slot], inited_key, max_unlock_mem, max_unlock_time, master_key);
	register_key_slot_as_used(decrypted_self, keyslot_key, target_slot);
	return target_slot;
}

#endif