//
// Created by level-128 on 8/24/23.
//

#include <sys/stat.h>
#include <inttypes.h>
#include <termios.h>
#include <libintl.h>

#define MIN_KEY_CHAR 7

#include "sha256.h"
#include "mapper.c"

struct SystemInfo {
	unsigned long free_ram;
	unsigned long free_swap;
	unsigned long total_ram;
};
struct SystemInfo sys_info;

typedef struct {
	char * key_or_keyfile_location;
	uint32_t key_type;
} Key;

enum {
	EMOBJ_key_file_type_input,
	EMOBJ_key_file_type_key,
	EMOBJ_key_file_type_file,
	EMOBJ_key_file_type_none,
};

bool is_skip_conformation = false;

char * crypt_list[] = {"aes", "twofish", "serpent", NULL};
char * chainmode_list[] = {"cbc", "xts", "ecb", NULL};
char * iv_list[] = {"plain64", "plain64be", "essiv", "eboiv", NULL};

// Why no #Pragma Once? Because this file should be only include once.

void is_running_as_root() {
	if (getuid() != 0) {
		print_error(_("The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible without root permission")) {}
	}
}

void ask_for_conformation(const char * format, ...) {
	if (is_skip_conformation) {
		return;
	}
	const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char random_str[4];
	char complete_str[10];
	char user_input[20];
	
	srand(time(NULL)); // NOLINT(*-msc51-cpp)
	
	for (int i = 0; i < 3; ++i) {
		int index = rand() % 64; // NOLINT(*-msc50-cpp)
		random_str[i] = base64_chars[index];
	}
	random_str[3] = '\0';
	
	printf("\033[1;33m%s\n", _("CONFORMATION REQUIRED: "));
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	sprintf(complete_str, "YES %s", random_str);
	printf(_("\nType \"%s\" to confirm."), complete_str);
	printf(" \033[0m\n");
	
	
	fgets(user_input, sizeof(user_input), stdin);
	user_input[strcspn(user_input, "\n")] = 0;
	if (strcmp(user_input, complete_str) != 0) {
		print_error(_("User has canceled the operation."));
	}
}

void get_system_info() {
	FILE * meminfo = fopen("/proc/meminfo", "r");
	if (meminfo == NULL) {
		print_warning(_("Failed to read system information. Can not determine adequate memory size (or memory limit) for key derivation."));
		sys_info.free_ram = ULLONG_MAX;
		sys_info.free_swap = ULLONG_MAX;
		return;
	}
	
	char line[256];
	unsigned long memFree = 0;
	unsigned long memTotal = 0;
	unsigned long cached = 0;
	unsigned long swapFree = 0;
	
	while (fgets(line, sizeof(line), meminfo)) {
		if (strncmp(line, "MemFree:", 8) == 0) {
			sscanf(line, "%*s %lu", &memFree);
		} else if (strncmp(line, "MemTotal:", 9) == 0) {
			sscanf(line, "%*s %lu", &memTotal);
		} else if (strncmp(line, "Cached:", 7) == 0) {
			sscanf(line, "%*s %lu", &cached);
		} else if (strncmp(line, "SwapFree:", 9) == 0) {
			sscanf(line, "%*s %lu", &swapFree);
		}
	}
	
	sys_info.free_ram = memFree + cached;
	sys_info.free_swap = swapFree;
	sys_info.total_ram = memTotal;
	
	fclose(meminfo);
}

void check_file(const char * filename, bool is_write, bool is_nofail) {
	if (access(filename, F_OK) != 0) {
		if (is_nofail){
			exit(0);
		}
		print_error(_("File %s does not exist"), filename);
	}
	
	if (access(filename, R_OK) != 0) {
		print_error(_("Cannot read %s: insufficient permission."), filename);
	}
	if (is_write && access(filename, W_OK) != 0) {
		print_error(_("Cannot write to %s: insufficient permission."), filename);
	}
	
	struct stat file_stat;
	if (stat(filename, &file_stat) != 0) {
		print_error(_("Cannot get size for %s"), filename);
	}
}

size_t check_target_mem(size_t target_mem, bool is_encrypt) {
	if (target_mem == 0) {
		if ((double) sys_info.free_ram / (double) sys_info.total_ram < 0.3) {
			print_warning(_("The system is low on memory (< 30%%). It is recommended to designate a larger allowed memory to utilize the system swap space via parameter \"%s\"."),
			              is_encrypt ? "--target-memory" : "--max-unlock-memory");
		}
		return sys_info.free_ram;
	}
	
	if (sys_info.free_ram < target_mem) {
		
		if ((sys_info.free_swap + sys_info.free_ram) > target_mem) {
			print_warning(_("using swap space for Key derivation function. This is potentially insecure because unencrypted swap space may provide hints to the master key."));
		} else {
			size_t new_target_mem = sys_info.free_swap + sys_info.free_ram - (1 << 16);
			if (is_encrypt) {
				ask_for_conformation(_("The RAM and swap are not enough to perform the suggested encryption parameters. Adjusted the max RAM consumption for Key derivation function"
				                       " from %lu (KiB) to %lu (KiB). This may degrade security, continue?"), target_mem, new_target_mem);
			} else {
				print_warning(_("Adjusted the requested max RAM consumption from %lu (KiB) to %lu (KiB) because of insufficient memory. "
				                "If your computer has less available memory than the computer who created the encryption target, you may not successfully decrypt this target. Consider adding more "
				                "swap spaces as a workaround."), target_mem, new_target_mem);
			}
			return new_target_mem;
		}
	}
	return target_mem;
}

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
		print_error(_("the key provided is too short (%zu characters), which is not recommended. To bypass this restriction, use argument --key instead."), strlen(key));
	}
	free(check_key);
	return key;
}

char * get_key_input_from_the_console_systemd(const char * device) {
	int pipefd[2];
	pid_t pid;
	char * buf = malloc(2049); // systemd-password allows 2048 bytes of password
	
	assert(pipe(pipefd) != -1);
	
	pid = vfork();
	assert(pid != -1);
	
	if (pid == 0) {
		close(pipefd[0]);
		
		assert(dup2(pipefd[1], STDOUT_FILENO) == -1);
		
		
		const char * const args[]={device, (char *) NULL};
		execvp("systemd-ask-password", (char * const *) args);
		
		print_error_no_exit("\"systemd-ask-password\" is not available. Param \"--systemd-dialog\" only supports system with systemd as init.");
		kill(getppid(), SIGQUIT);
		exit(1);
	}
	
	close(pipefd[1]);
	
	ssize_t num_read = read(pipefd[0], buf, sizeof(buf) - 1);
	assert(num_read != -1);

	buf[num_read] = '\0';
	return buf;
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

void init_key(const Key key, uint8_t inited_key[HASHLEN]) {
	size_t key_size;
	if (key.key_type == EMOBJ_key_file_type_file) {
		uint8_t * key_buffer = read_key_file(key, &key_size);
		sha256_digest_all(key_buffer, key_size, inited_key);
		free(key_buffer);
	} else {
		sha256_digest_all(key.key_or_keyfile_location, strlen(key.key_or_keyfile_location), inited_key);
	}
	if (key.key_type == EMOBJ_key_file_type_input) {
		free(key.key_or_keyfile_location);
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

int get_master_key(Data self, uint8_t master_key[HASHLEN], const Key key, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	if (key.key_type == EMOBJ_key_file_type_none){ // uses master key
		return -1;
	}
	uint8_t inited_key[HASHLEN];
	uint8_t inited_keys[KEY_SLOT_COUNT][HASHLEN];
	init_key(key, inited_key);
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
	} else if (unlocked_slot == NMOBJ_STEP_ERR_TIMEOUT){
		print_error(_("Cannot unlock the target probably due to incorrect key.\n"
		              "\tIf you are certain that the key is indeed correct, because the time limit has reached, try increasing the maximum time limit "
		              "using --max-unlock-time."));
	} else if (unlocked_slot == NMOBJ_STEP_ERR_END){
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


int add_key_to_keyslot(Data * decrypted_self, const uint8_t master_key[32], const Key key, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t inited_key[HASHLEN];
	uint8_t keyslot_key[HASHLEN];
	
	init_key(key, inited_key);
	
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

char * interactive_ask_new_key_test_key = NULL;

void interactive_ask_new_key(Key * new_key, const char * device) {
	char option;
	if (interactive_ask_new_key_test_key == NULL) {
		printf(_("AddKey: choose your key format \n(1) input key from console;\n(2) use a key file\nOption: \n"));
		
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
			new_key->key_or_keyfile_location = get_key_input_from_the_console(device, true);
		} else {
			new_key->key_or_keyfile_location = malloc(strlen(interactive_ask_new_key_test_key) + 1);
			strcpy(new_key->key_or_keyfile_location, interactive_ask_new_key_test_key);
			interactive_ask_new_key_test_key = NULL;
		}
		new_key->key_type = EMOBJ_key_file_type_input;
	} else if (option == '2') {
		char * file_location;
		size_t len;
		printf("Key file location:");
		getline(&file_location, &len, stdin);
		new_key->key_or_keyfile_location = file_location;
		new_key->key_type = EMOBJ_key_file_type_file;
	}
}


void check_encryption_mode_arg(const char * str, int64_t idx[3]) {
	int dash_count = 0;
	for (int i = 0; str[i] != '\0'; i++) {
		if (str[i] == '-') {
			dash_count++;
		}
	}
	if (dash_count != 2) {
		print_error(_("Invalid argument. The encryption scheme should obey the format: \"*cipher*-*chainmode*-*ivmode*\""));
	}
	char * strcpy = strdup(str);
	
	char * token = strtok(strcpy, "-");
	idx[0] = is_in_list(token, crypt_list);
	if (idx[0] == -1) {
		print_error(_("Invalid argument. Unrecognized cipher \"%s\". "), token);
	}
	
	token = strtok(NULL, "-");
	idx[1] = is_in_list(token, chainmode_list);
	if (idx[1] == -1) {
		print_error(_("Invalid argument. Unrecognized chainmode \"%s\". "), token);
	}
	
	token = strtok(NULL, "-");
	idx[2] = is_in_list(token, iv_list);
	if (idx[2] == -1) {
		print_error(_("Invalid argument. Unrecognized ivmode \"%s\". "), token);
	}
	free(strcpy);
}

void action_new_check_crypt_support_status(const char * str) {
	int64_t idx[3];
	check_encryption_mode_arg(str, idx);
	char ** crypto_list = get_crypto_list();
	
	if (crypto_list == NULL) {
		return;
	}
	
	char chainmode_name[32];
	sprintf(chainmode_name, "%s(%s)", chainmode_list[idx[1]], crypt_list[idx[0]]);
	if (is_in_list(chainmode_name, crypto_list) == -1) {
		ask_for_conformation(_("The cipher %s you've requested might not be supported by your current system. Although you can create a header that employs this encryption scheme, "
		                       "your system might not be capable of unlocking it. This means you won't be able to access the encrypted device you've just created with this specific "
									  "method on this system. You would need to locate a compatible system, recompile your kernel, or find the appropriate kernel module to access the "
									  "device. Do you wish to proceed?"), chainmode_name);
	}
	
	for (int i = 0; crypto_list[i]; i++) {
		free(crypto_list[i]);
	}
	free(crypto_list);
}

#define OPERATION_READ_HEADER \
Data data;          \
if (is_decoy == true){ \
    print_warning(_("Unlocking %s assuming decoy partition exits"), device);   \
}                    \
is_decoy = detect_fat32_on_device(device); \
int64_t offset = is_decoy ? -(int64_t)sizeof(Data) : 0;                            \
get_header_from_device(&data, device, offset); \

#define OPERATION_DECLINE_SUSPEND \
if (is_header_suspended(data)){   \
print_error(_("The header is suspended. Resume header to perform this operation.")); \
}


#define OPERATION_BACKEND_UNENCRYPT_HEADER    \
[[maybe_unused]] int unlocked_slot = get_master_key(data, master_key, key, target_unlock_slot, max_unlock_mem, max_unlock_time); \
                                              \
if (lock_or_unlock_metadata_using_master_key(&data, master_key) == false) {\
print_error(key.key_type != EMOBJ_key_file_type_none ? _("This key has been revoked.") : _("Wrong master key."));\
}                                  \
operate_all_keyslots_using_keyslot_key_in_metadata(data.keyslots, data.metadata.keyslot_key, data.master_key_mask, true); /* open all key slots */ \
bool revoked_untagged_slot[KEY_SLOT_COUNT];              \
check_master_key_and_slots_revoke(&data, revoked_untagged_slot);\
for (int i = 0; i < KEY_SLOT_COUNT; i++){                \
if (revoked_untagged_slot[i] == true){     \
print_warning(_("Slot %i on device %s have been revoked without using the password."), i, device);                    \
}}                                  \

#define OPERATION_LOCK_AND_WRITE \
assign_new_header_iv(&data);\
operate_all_keyslots_using_keyslot_key_in_metadata(data.keyslots, data.metadata.keyslot_key, data.master_key_mask, false);\
lock_or_unlock_metadata_using_master_key(&data, master_key);\
write_header_to_device(&data, device, offset);

#define PARAMS_FOR_KEY Key key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double max_unlock_time, bool is_decoy

void action_create(const char * device, const char * enc_type, const Key key, int target_slot, size_t target_memory, double target_time, bool is_decoy, size_t block_size) {
	Data data;
	uint8_t master_key[HASHLEN];
	size_t start_sector, end_sector;
	int64_t offset = is_decoy ? -(int64_t) sizeof(Data) : 0;
	action_new_check_crypt_support_status(enc_type);
	check_is_device_mounted(device);
	
	ask_for_conformation(_("Creating encrypt partition on device: %s, All content will be lost. Continue?"), device);
	
	fill_secure_random_bits(master_key, HASHLEN);
	decide_start_and_end_sector(device, is_decoy, &start_sector, &end_sector, block_size);
	initialize_new_header(&data, enc_type, start_sector, end_sector, block_size);
	add_key_to_keyslot(&data, master_key, key, target_slot, target_memory, target_time);
	
	OPERATION_LOCK_AND_WRITE
	
	if (is_decoy) {
		create_fat32_on_device(device);
	}
}

bool action_open_suspended_or_keyring(const char * device, const char * target_name, bool is_decoy, bool is_dry_run, bool is_target_readonly, bool is_allow_discards, bool is_no_read_workqueue,
                                      bool is_no_write_workqueue) {
	OPERATION_READ_HEADER

	
	if (is_header_suspended(data)) {
		if (!is_dry_run) {
			uint8_t zeros[HASHLEN] = {0}, disk_key[HASHLEN];
			get_metadata_key_or_disk_key_from_master_key(data.metadata.disk_key_mask, zeros, data.uuid_and_salt, disk_key);
			create_crypt_mapping_from_disk_key(device, target_name, &data.metadata, disk_key, data.uuid_and_salt, false, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);
			print_warning(_("Device %s is unlocked and suspended. Don't forget to close it using \"Resume\" when appropriate."), device);
		} else {
			char uuid_str[37];
			generate_UUID_from_bytes(data.uuid_and_salt, uuid_str);
			printf(_("dry run complete. Device is unlocked and suspended, thus no key slot status could be provided\n"));
			printf(_("Additional device parameters: \n"
			         "UUID: %s\n"
			         "Crypto algorithm: %s\n"
			         "Start sector %lu\n"
			         "End sector %lu\n"
			         "Block size %hu\n"), uuid_str, data.metadata.enc_type, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size);
		}
		return true;
	}
	switch (mapper_keyring_get_serial(data.uuid_and_salt)) {
		case NMOBJ_KEY_OK:
			printf(_("Found kernel keyring key\n"));
			create_crypt_mapping_from_disk_key(device, target_name, &data.metadata, NULL, data.uuid_and_salt, true, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);
			return true;
		case NMOBJ_KEY_ERR_NOKEY:
			printf(_("Unlocking %s to /dev/mapper/%s...\n"), device, target_name);
			break;
		case NMOBJ_KEY_ERR_KEYREVOKED:
		print_warning(_("The stored key in kernel keyring subsystem has removed."));
			break;
		case NMOBJ_KEY_ERR_KEYEXPIRED:
		print_warning(_("The stored key in kernel keyring subsystem has expired."));
			break;
		case NMOBJ_KEY_ERR_KERNEL_KEYRING:
		print_warning(_("Kernel keyring subsystem cannot be loaded. Kernel keyring is not required but strongly recommended."));
			break;
	}
	return false;
	
}

void action_open(const char * device, const char * target_name, PARAMS_FOR_KEY, unsigned timeout, bool is_dry_run, bool is_target_readonly, bool is_allow_discards, bool is_no_read_workqueue, bool is_no_write_workqueue) {
	
	OPERATION_READ_HEADER
	OPERATION_BACKEND_UNENCRYPT_HEADER
	
	if (!is_dry_run) {
		uint8_t disk_key[HASHLEN];
		get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, data.uuid_and_salt, disk_key);
		if (timeout){
			printf(_("Registering the key into keyring with lifetime: %u sec.\n"), timeout);
			mapper_keyring_add_key(disk_key, data.uuid_and_salt, timeout);
		}
		create_crypt_mapping_from_disk_key(device, target_name, &data.metadata, disk_key, data.uuid_and_salt, false, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);

	} else {
		char uuid_str[37];
		generate_UUID_from_bytes(data.uuid_and_salt, uuid_str);
		printf(_("dry run complete. Slot %i opened with master key:\n"), unlocked_slot);
		print_hex_array(HASHLEN, master_key);
		printf(_("Additional device parameters: \n"
		         "UUID: %s\n"
		         "Crypto algorithm: %s\n"
		         "Start sector %lu\n"
		         "End sector %lu\n"
		         "Block size %hu\n"), uuid_str, data.metadata.enc_type, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size);
		printf(_("key slot status:\n"));
		
		uint8_t temp[HASHLEN] = {0};
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			if (data.metadata.key_slot_is_used[i]) {
				if (memcmp(data.metadata.keyslot_key[i], temp, HASHLEN) == 0){
					printf(_("Slot %i has been revoked.\n"), i);
				} else {
					printf(_("Slot %i occupied with password; identifier: "), i);
					print_hex_array(HASHLEN / 4, data.metadata.keyslot_key[i]);
				}
			} else {
				printf(_("Slot %i is empty.\n"), i);
			}
		}
	}
}

void action_close(const char * device) {
	char device_loc[strlen(device) + strlen("/dev/mapper/") + 1];
	sprintf(device_loc, "/dev/mapper/%s", device);
	check_is_device_mounted(device_loc);
	remove_crypt_mapping(device);
}

int action_addkey(const char * device, PARAMS_FOR_KEY, int target_slot, uint64_t target_memory, double target_time) {
	OPERATION_READ_HEADER
	OPERATION_DECLINE_SUSPEND
	OPERATION_BACKEND_UNENCRYPT_HEADER
	
	Key new_key;
	interactive_ask_new_key(&new_key, device);
	int added_slot = add_key_to_keyslot(&data, master_key, new_key, target_slot, target_memory, target_time);
	
	OPERATION_LOCK_AND_WRITE
	return added_slot;
}

int action_revokekey(const char * device, PARAMS_FOR_KEY, bool is_revoke_all, bool is_obliterate) {
	OPERATION_READ_HEADER
	if (is_revoke_all) {
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			revoke_given_key_slot(&data, i, false);
		}
		write_header_to_device(&data, device, offset);
		return -1;
	} else if (is_obliterate) {
		ask_for_conformation(_("Device %s will not be accessible, even if holding the master key, unless backup has created. Continue?"), device);
		for (int i = 0; i < 3; i++) {
			fill_secure_random_bits((uint8_t *) &data, sizeof(Data));
			write_header_to_device(&data, device, offset);
		}
		return -1;
	} else if (target_unlock_slot != -1) {
		revoke_given_key_slot(&data, target_unlock_slot, false);
		write_header_to_device(&data, device, offset);
		return target_unlock_slot;
	}
	
	OPERATION_DECLINE_SUSPEND
	OPERATION_BACKEND_UNENCRYPT_HEADER
	
	revoke_given_key_slot(&data, unlocked_slot, true);
	
	OPERATION_LOCK_AND_WRITE
	return unlocked_slot;
}

void action_backup(const char * device, const char * filename, PARAMS_FOR_KEY, bool is_no_transform) {
	if (access(filename, F_OK) != -1) {
		print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename) {}
	}
	OPERATION_READ_HEADER
	OPERATION_DECLINE_SUSPEND
	if (is_no_transform) {
		write_header_to_device(&data, filename, 0);
	} else {
		OPERATION_BACKEND_UNENCRYPT_HEADER
		device = filename;
		offset = 0;
		OPERATION_LOCK_AND_WRITE
	}
}

void action_restore(const char * device, const char * filename, bool is_decoy) {
	ask_for_conformation(_("Restoring header to device: %s, All content will be lost. Continue?"), device);
	swap(device, filename);
	OPERATION_READ_HEADER
	swap(device, filename);
	is_decoy = is_decoy || detect_fat32_on_device(device);
	write_header_to_device(&data, device, is_decoy ? -(int64_t) sizeof(Data) : 0);
}

void action_suspend(const char * device, PARAMS_FOR_KEY) {
	OPERATION_READ_HEADER
	if (is_header_suspended(data)) {
		print_error(_("The device %s is already suspended."), device);
	}
	Data data_copy;
	memcpy(&data_copy, &data, sizeof(data_copy));
	OPERATION_BACKEND_UNENCRYPT_HEADER // get master key and validate
	do {
		suspend_encryption(&data_copy, master_key);
		write_header_to_device(&data_copy, device, offset);
	} while (0);
}

void action_resume(const char * device, PARAMS_FOR_KEY) {
	OPERATION_READ_HEADER
	if (!is_header_suspended(data)) {
		print_error(_("The device %s is already encrypted."), device);
	}
	Data data_copy;
	memcpy(&data_copy, &data, sizeof(data_copy));
	// unlock the header but not validate key using metadata. metadata is a mess right now.
	get_master_key(data, master_key, key, target_unlock_slot, max_unlock_mem, max_unlock_time);
	
	resume_encryption(&data_copy, master_key);
	write_header_to_device(&data_copy, device, offset);
}

void init(bool enable_kernel_keyring) {
	init_enclib("/dev/urandom");
	get_system_info();
	mapper_init();
	check_container();
}
