//
// Created by level-128 on 1/19/24.
//

#ifndef INCL_BKLIBKEY
#define INCL_BKLIBKEY

#include <windham_const.h>
#include <termios.h>

#include "bksrclib.c"


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
	check_file(filename, false, false);
	
	FILE * file = fopen(filename, "rb");
	
	fseek(file, 0, SEEK_END);
	*length = ftell(file);
	fseek(file, 0, SEEK_SET);
	
	uint8_t * buffer = malloc(*length);
	
	fread(buffer, 1, *length, file);
	fclose(file);
	
	return buffer;
}

void prepare_key(const Key key, uint8_t inited_key[HASHLEN], const char * device) {
	size_t key_size;
	char * input_key = NULL;
	
	switch (key.key_type) {
		case EMOBJ_key_file_type_masterkey:
			break;
		case EMOBJ_key_file_type_input:
			input_key = get_key_input_from_the_console(device, true);
			sha256_digest_all(input_key, strlen(input_key), inited_key);
			break;
		case EMOBJ_key_file_type_input_systemd:
			input_key = get_key_input_from_the_console_systemd(device);
			sha256_digest_all(input_key, strlen(input_key), inited_key);
			break;
		case EMOBJ_key_file_type_file:
			input_key = (char *) read_key_file(key, &key_size);
			sha256_digest_all(input_key, key_size, inited_key);
			break;
		case EMOBJ_key_file_type_key:
			sha256_digest_all(key.key_or_keyfile_location, strlen(key.key_or_keyfile_location), inited_key);
	}
	free(input_key);
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

int add_key_to_keyslot(Data * decrypted_self, const uint8_t master_key[32], const Key key, const char * device, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t inited_key[HASHLEN];
	uint8_t keyslot_key[HASHLEN];
	
	prepare_key(key, inited_key, device);
	
	// select slot
	if ((target_slot = select_available_key_slot(decrypted_self->metadata, target_slot, decrypted_self->keyslots)) == -1) {
		print_error(_("All key slots are full. Remove or revoke one or more keys to add a new key."));
	}
	
	get_keyslot_key_from_inited_key(inited_key, decrypted_self->uuid_and_salt, keyslot_key);
	
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		if (memcmp(decrypted_self->metadata.keyslot_key[i], keyslot_key, HASHLEN) == 0) {
			print_error(_("The given key is used at slot %i"), i);
		}
	}
	
	max_unlock_mem = check_target_mem(max_unlock_mem, true);
	
	set_master_key_to_slot(&decrypted_self->keyslots[target_slot], inited_key, max_unlock_mem, max_unlock_time, master_key);
	register_key_slot_as_used(decrypted_self, keyslot_key, target_slot);
	return target_slot;
}

#endif