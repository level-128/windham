//
// Created by level-128 on 8/24/23.
//

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <stdint.h>
#include <termios.h>
#include <libintl.h>

#define MIN_KEY_CHAR 7


#include "sha256.h"
#include "mapper.c"

struct SystemInfo {
	unsigned long free_ram;
	unsigned long free_swap;
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
	char random_str[5];
	char complete_str[10];
	char user_input[20];
	
	srand(time(NULL)); // NOLINT(*-msc51-cpp)
	
	for (int i = 0; i < 4; ++i) {
		int index = rand() % 64; // NOLINT(*-msc50-cpp)
		random_str[i] = base64_chars[index];
	}
	random_str[4] = '\0';
	
	printf("\033[1;33m%s\n", _("CONFORMATION REQUIRED: "));
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf(_("Type \"YES %s\" to confirm."), random_str);
	printf(" \033[0m\n");
	sprintf(complete_str, "YES %s", random_str);
	
	fgets(user_input, sizeof(user_input), stdin);
	user_input[strcspn(user_input, "\n")] = 0;
	if (strcmp(user_input, complete_str) != 0) {
		print_error(_("User has canceled the operation."));
	}
}

void get_system_info() {
	struct sysinfo info;
	if (sysinfo(&info) == -1) {
		print_warning(_("Failed to read system information. Can not determine adequate memory size (or memory limit) for key derivation."));
		sys_info.free_ram = ULLONG_MAX;
		sys_info.free_swap = ULLONG_MAX;
		
	} else {
		sys_info.free_ram = sysconf(_SC_AVPHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;
		sys_info.free_swap = info.freeswap / 1024;
//		print("free mem", sys_info.free_ram, "sys_info.free_swap", sys_info.free_swap);
	}
}

void check_file(const char * filename, bool is_block) {
	if (access(filename, F_OK) != 0) {
		print_error(_("File %s does not exist"), filename);
	}
	
	if (access(filename, R_OK) != 0) {
		print_error(_("Cannot read %s: insufficient permission."), filename);
	}
	if (is_block && access(filename, W_OK) != 0) {
		print_error(_("Cannot write to %s: insufficient permission."), filename);
	}
	
	struct stat file_stat;
	if (stat(filename, &file_stat) != 0) {
		print_error(_("Cannot get size for %s"), filename);
	}
}

size_t check_target_mem(size_t target_mem, bool is_encrypt) {
	if (target_mem == 0) {
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


char * get_input() {
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

char * get_key_input_from_the_console() {
	char * key, * check_key;
	print(_("Password:"));
	key = get_input();
	print(_("Again:"));
	check_key = get_input();
	if (strcmp(key, check_key) != 0) {
		print_error(_("Passwords do not match."));
	} else if (strlen(key) < MIN_KEY_CHAR) {
		print_error(_("the key provided is too short (%zu characters), which is not recommended. To bypass this restriction, use argument --key instead."), strlen(key));
	}
	free(check_key);
	return key;
}

uint8_t * read_key_file(const Key key, size_t * length) {
	char * filename = key.key_or_keyfile_location;
	check_file(filename, false);
	
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
		srand((unsigned)time(NULL));
		
		for (int i = KEY_SLOT_COUNT - 1; i > 0; i--) {
			int j = rand() % (i + 1);
			int temp = slot_seq[i];
			slot_seq[i] = slot_seq[j];
			slot_seq[j] = temp;
			slot_seq[KEY_SLOT_COUNT] = -1;
		}
	} else {
		slot_seq[0] = target_slot;
		slot_seq[1] = -1;
	}
}

int get_master_key(Data self, uint8_t master_key[HASHLEN], const Key key, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t inited_key[HASHLEN];
	uint8_t inited_keys[KEY_SLOT_COUNT][HASHLEN];
	init_key(key, inited_key);
	
	max_unlock_mem = check_target_mem(max_unlock_mem, false);
	
	int slot_seq[KEY_SLOT_COUNT + 1];
	get_slot_list_for_get_master_key(slot_seq, target_slot);
	
	for (int i = 0; slot_seq[i] != -1; i++){
		operate_key_slot_using_inited_key(&self.keys[slot_seq[i]], inited_key, self.master_key_mask, true);
		memcpy(inited_keys[slot_seq[i]], inited_key, HASHLEN);
	}
	
	int unlocked_slot = read_key_from_all_slots(self.keys, inited_keys, slot_seq, max_unlock_mem, max_unlock_time);
	if (unlocked_slot != -1) {
		xor_with_len(HASHLEN, inited_keys[unlocked_slot], self.keys[unlocked_slot].key_mask, master_key);
	} else {
		print_error(_("Cannot unlock target because time or memory limit has reached. This is probably because a wrong key "
		            "has been provided, or your compute resources may be too insufficient to unlock the target created "
		            "by a faster computer within the preset time. If the latter is correct, try increasing the maximum memory limit "
		            "using --max-unlock-memory. If the operation cannot be completed due to insufficient system "
		            "memory, consider exporting the master key on a more computationally powerful device and then use the "
		            "master key to unlock the target."));
	}
	return unlocked_slot;
}

int check_is_duplicate_and_get_slot(Data decrypted_self, uint8_t inited_key[HASHLEN], int target_slot) {
	if ((target_slot = select_available_key_slot(decrypted_self.metadata, target_slot, decrypted_self.keys)) == -1) {
		print_error(_("All key slots are full. Remove or revoke one or more keys to add a new key."));
	}
	
	//check is duplicate
	for (int i = 0; i < KEY_SLOT_COUNT; i++) {
		if (memcmp(decrypted_self.metadata.inited_key[i], inited_key, HASHLEN) == 0) {
			print_error(_("The given key is used at slot %i"), i);
		}
	}
	return target_slot;
}

int add_key(Data * decrypted_data, const uint8_t master_key[32], const Key key, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t password_hash[HASHLEN];
	uint8_t inited_key[HASHLEN];
	
	init_key(key, inited_key);
	
	// select slot
	target_slot = check_is_duplicate_and_get_slot(*decrypted_data, inited_key, target_slot);
	
	max_unlock_mem = check_target_mem(max_unlock_mem, true);
	
	memcpy(password_hash, inited_key, HASHLEN);
	set_master_key_to_slot(&decrypted_data->keys[target_slot], password_hash, max_unlock_mem, max_unlock_time, master_key);
	register_key_slot_as_used(decrypted_data, inited_key, target_slot);
	return target_slot;
}

void interactive_ask_new_key(Key * new_key) {
	char option;
	print(_("AddKey: choose your key format \n(1) input key from console;\n(2) use a key file\nOption: "));
	
	struct termios oldt, newt;
	
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	
	option = (char) getchar();
	
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	
	print("");
	if (option == '1') {
		new_key->key_or_keyfile_location = get_key_input_from_the_console();
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

#define READ_HEADER \
Data data;          \
if (is_decoy == true){ \
    print_warning(_("Unlocking %s assuming decoy partition exits"), device);   \
}                    \
is_decoy = detect_fat32_on_device(device); \
int64_t offset = is_decoy ? -(int64_t)sizeof(Data) : 0;                            \
get_header_from_device(&data, device, offset); \


#define OPERATION_BACKEND_UNLOCK    \
    READ_HEADER \
[[maybe_unused]] int unlocked_slot = -1;                 \
if (key.key_type != EMOBJ_key_file_type_none){\
unlocked_slot = get_master_key(data, master_key, key, target_unlock_slot, max_unlock_mem, max_unlock_time);\
}\
if (operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask) == false) {\
print_error(key.key_type != EMOBJ_key_file_type_none ? _("This key has been revoked.") : _("Wrong master key."));\
}                                  \
operate_all_keyslots(data.keys, data.metadata.inited_key, data.master_key_mask, true);                                    \
bool revoked_untagged_slot[KEY_SLOT_COUNT];              \
check_master_key_and_slots_revoke(&data, revoked_untagged_slot);\
for (int i = 0; i < KEY_SLOT_COUNT; i++){                \
if (revoked_untagged_slot[i] == true){     \
print_warning("Slot %i on device %s have been revoked without using the password.", i, device);                    \
}}                                  \

#define OPERATION_LOCK_AND_WRITE \
transform_header(&data);\
operate_all_keyslots(data.keys, data.metadata.inited_key, data.master_key_mask, false);\
operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask);\
write_header_to_device(&data, device, offset);

void action_create(const char * device, const char * enc_type, const Key key, int target_slot, uint64_t target_memory, double target_time, bool is_decoy) {
	Data data;
	uint8_t master_key[HASHLEN];
	size_t start_sector, end_sector;
	int64_t offset = is_decoy ? -(int64_t) sizeof(Data) : 0;
	
	ask_for_conformation(_("Creating encrypt partition on device: %s, All content will be lost. Continue?"), device);
	
	decide_start_and_end_sector(device, is_decoy, &start_sector, &end_sector);
	initialize_new_header(&data, enc_type, start_sector, end_sector);
	add_key(&data, master_key, key, target_slot, target_memory, target_time);
	
	OPERATION_LOCK_AND_WRITE
	
	if (is_decoy) {
		create_fat32_on_device(device);
	}
}

int action_open(const char * device, const char * target_name, Key key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double
max_unlock_time, bool is_target_readonly, bool is_dry_run, bool is_decoy) {
	
	OPERATION_BACKEND_UNLOCK
	
	if (!is_dry_run) {
		uint8_t disk_key[HASHLEN];
		get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, disk_key);
		create_crypt_mapping_from_disk_key(device, target_name, data.metadata, disk_key, is_target_readonly);
	}
	return unlocked_slot;
}

void action_close(const char * device) {
	remove_crypt_mapping(device);
}

int action_addkey(const char * device, const Key key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double max_unlock_time, int target_slot,
                  uint64_t target_memory,
                  double target_time, bool is_decoy) {
	
	OPERATION_BACKEND_UNLOCK
	
	Key new_key;
	interactive_ask_new_key(&new_key);
	int added_slot = add_key(&data, master_key, new_key, target_slot, target_memory, target_time);
	
	OPERATION_LOCK_AND_WRITE
	return added_slot;
}

int action_revokekey(const char * device, const Key key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double max_unlock_time,
                     bool is_revoke_all, bool is_obliterate, bool is_decoy) {
	
	if (is_revoke_all) {
		READ_HEADER
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			revoke_given_key_slot(&data, i, false);
		}
		write_header_to_device(&data, device, offset);
		return -1;
	} else if (is_obliterate) {
		READ_HEADER
		ask_for_conformation(_("Device %s will not be accessible, even if holding the master key, unless backup has created. Continue?"), device);
		for (int i = 0; i < 3; i++) {
			fill_secure_random_bits((uint8_t *) &data, sizeof(Data));
			write_header_to_device(&data, device, offset);
		}
		return -1;
	} else if (target_unlock_slot != -1) {
		READ_HEADER
		revoke_given_key_slot(&data, target_unlock_slot, false);
		write_header_to_device(&data, device, offset);
		return target_unlock_slot;
	}
	
	
	OPERATION_BACKEND_UNLOCK
	
	revoke_given_key_slot(&data, unlocked_slot, true);
	
	OPERATION_LOCK_AND_WRITE
	return unlocked_slot;
}

void action_backup(const char * device, const char * filename, const Key key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double
max_unlock_time, bool is_decoy, bool is_no_transform, bool is_restore) {
	if (access(filename, F_OK) != -1) {
		print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename) {}
	}
	if (is_no_transform) {
		READ_HEADER
		write_header_to_device(&data, filename, offset);
	} else if (is_restore) {
		ask_for_conformation(_("Restoring header to device: %s, All content will be lost. Continue?"), device);
		const char * _;
		_ = device;
		device = filename;
		filename = _;
		READ_HEADER
		write_header_to_device(&data, filename, offset);
	} else {
		OPERATION_BACKEND_UNLOCK
		device = filename;
		OPERATION_LOCK_AND_WRITE
	}
}

void init() {
	init_random_generator("/dev/urandom");
	get_system_info();
	mapper_init();
}
