//
// Created by level-128 on 8/24/23.
//

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <termios.h>

#define MIN_KEY_CHAR 7



#include "sha256.h"
#include "mapper.c"

struct SystemInfo {
	unsigned long free_ram;
	unsigned long total_swap;
	unsigned long free_swap;
	long num_processors;
};
struct SystemInfo sys_info;

typedef struct {
	char * key_or_keyfile_location;
	uint32_t key_type;
} Key;

enum {
	EMOBJ_key_file_type_input,
	EMOBJ_key_file_type_key,
	EMOBJ_key_file_type_file
};

void print_hex_array(size_t length, const uint8_t arr[length]) {
	for (size_t i = 0; i < length; ++i) {
		printf("%02x ", arr[i]);
	}
	printf("\n");
}

//void print_key(Key * key)(


void is_running_as_root() {
	if (getuid() != 0) {
		print_error("The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible without root permission");
	}
}

void ask_for_conformation(const char *format, ...){
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
	
	printf("\033[1;33mCONFORMATION REQUIRED: ");
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\nType \"YES ");
	printf("%s\" to confirm. \033[0m\n", random_str);
	sprintf(complete_str, "YES %s", random_str);
	
	fgets(user_input, sizeof(user_input), stdin);
	user_input[strcspn(user_input, "\n")] = 0;
	if (strcmp(user_input, complete_str) != 0){
		print_error("User canceled the operation.");
	}
}

void get_system_info() {
	struct sysinfo info;
	if (sysinfo(&info) == -1) {
		print_warning("Failed to read system information. Can not determine adequate memory size for key derivation.");
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
		print_error("File does not exist:", filename);
	}
	
	if (access(filename, R_OK) != 0) {
		print_error("Cannot read file", filename);
	}
	if (is_block && access(filename, W_OK) != 0) {
		print_error("Cannot write to file", filename);
	}
	
	struct stat file_stat;
	if (stat(filename, &file_stat) != 0) {
		print_error("Cannot get file size", filename);
	}
	off_t file_size = file_stat.st_size;
	
	
	if (is_block && file_size < 4096) {
		print_error("block device is less than 4 KiB");
	}
}

size_t check_target_mem(size_t target_mem, bool is_encrypt){
	if (sys_info.free_ram < target_mem){
		if ((sys_info.free_swap + sys_info.free_ram) > target_mem){
			print_warning("using swap space for Key derivation function. This is potentially insecure because unencrypted swap space may provide hints to the master key.");
			return target_mem;
		}
		
		size_t new_target_mem = sys_info.free_swap + sys_info.free_ram - (1 << 16);
		if (is_encrypt) {
			ask_for_conformation("The RAM and swap are not enough to perform the suggested encryption parameters. Adjusted the max RAM consumption for Key derivation function"
										" from %lu (KiB) to %lu (KiB). This may degrade security, continue?", target_mem, new_target_mem);
		} else {
			print_warning("Adjusted the max RAM consumption for Key Derivation Function when trying each passphrase slot from %lu (KiB) to %lu (KiB) because of insufficient memory. "
							  "If your computer is much slower than the computer which created the encryption target, you may not successfully decrypt this target. Consider adding more "
							  "swap spaces as a workaround.", target_mem, new_target_mem);
		}
		return new_target_mem;
	}
	return target_mem;
}


char* get_input() {
	struct termios oldt, newt;
	int size = 20;
	char *input = (char *) malloc(size * sizeof(char));
	char ch;
	int index = 0;

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	
	while (1) {
		ch = (char)getchar();
		
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
	print("key:");
	key = get_input();
	print("Again:");
	check_key = get_input();
	if (strcmp(key, check_key) != 0) {
		print_error("Passwords do not match.");
	} else if (strlen(key) < MIN_KEY_CHAR) {
		print_error("the key provided is too short (",  strlen(key), "characters), which is not recommended. To bypass this restriction, use --key instead.");
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

int get_master_key(Data self, uint8_t master_key[HASHLEN], const Key key, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t password_hash_all_slots[KEY_SLOT_COUNT][HASHLEN]; // calculating hash in password_hash_all_slots
	uint8_t inited_key[HASHLEN];
	init_key(key, inited_key);
	
	uint64_t mem_size_limit = calc_initial_pw_hash_and_iter_cnt(&self, inited_key, target_slot, max_unlock_mem, max_unlock_time, password_hash_all_slots, NULL);
	mem_size_limit = check_target_mem(mem_size_limit, false);
	
	int key_slot_count;
	if (target_slot == -1){
		key_slot_count = KEY_SLOT_COUNT;
		target_slot = 0;
	} else {
		key_slot_count = target_slot + 1;
	}
	for (; target_slot < key_slot_count; target_slot++) {
		if (! get_master_key_from_slot(&self.keys[target_slot], password_hash_all_slots[target_slot], mem_size_limit, master_key)) {
			continue;
		}
		return target_slot;
	}
	print_error("Cannot unlock the target because time or memory limit has reached. This is probably because a wrong key\n"
					"has been provided, or your compute resources may be too insufficient to unlock the target created\n"
					"by a faster computer. If the latter is correct, then consider increasing the maximum runtime\n"
					"limit (which will result in using more memory). If the operation cannot be completed due to lack of\n"
					"memory, consider exporting the master key on a more computationally powerful device and then use the\n"
					"master key to unlock the target.");

}


int add_key_from_decrypted_data_using_master_key(Data * decrypted_self, const uint8_t master_key[32], const Key key, int target_slot, uint64_t max_unlock_mem, double
max_unlock_time) {
	uint8_t password_hash[HASHLEN];
	uint8_t inited_key[HASHLEN];
//	print("add_key_from_decrypted_data_using_master_key:");
	
	init_key(key, inited_key);
	
	// select slot
	if ((target_slot = select_available_key_slot(decrypted_self->metadata, target_slot, decrypted_self->keys)) == -1) {
		print_error("All key slots are full. Remove or revoke one or more keys to add new key.");
	}
	
	//check is duplicate
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		if (memcmp(decrypted_self->metadata.inited_key[i], inited_key, HASHLEN) == 0){
			print_error("The given key is used at slot", i);
		}
	}
	
	uint64_t mem_size_limit = calc_initial_pw_hash_and_iter_cnt(decrypted_self, inited_key, target_slot, max_unlock_mem, max_unlock_time, NULL, password_hash);
	mem_size_limit = check_target_mem(mem_size_limit, true);

	set_master_key_to_slot(&decrypted_self->keys[target_slot], password_hash, mem_size_limit, master_key);
	register_key_slot_as_used(decrypted_self, inited_key, target_slot);
	return target_slot;
}

void interactive_ask_new_key(Key * new_key){
	char option;
	print("Adding a new key. Choose your key format: \n(1) input key from console;\n(2) use a key file\nOption: ");
	
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
    print_warning("Unlocking", device, "assuming decoy partition exits");   \
}                    \
is_decoy = detect_fat32_on_device(device); \
int64_t offset = is_decoy ? -sizeof(Data) : 0;                            \
get_header_from_device(&data, device, offset); \




#define OPERATION_BACKEND_UNLOCK 	 \
    READ_HEADER \
[[maybe_unused]] int unlocked_slot = -1;                 \
if (key != NULL){\
unlocked_slot = get_master_key(data, master_key, *key, target_unlock_slot, max_unlock_mem, max_unlock_time);\
}\
;           \
if (operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask) == false) {\
print_error(key != NULL ? "This key has been revoked. " : "Wrong master key.");\
}                                  \
bool revoked_untagged_slot[KEY_SLOT_COUNT];              \
check_master_key_and_slots_revoke(&data, revoked_untagged_slot);\
for (int i = 0; i < KEY_SLOT_COUNT; i++){                \
if (revoked_untagged_slot[i] == true){     \
print_warning("Slot", i, "on device", device, "have been revoked without unlock.");                    \
}                                   \
}                                   \
\



void action_create(const char * device, const char * enc_type, const Key key, int target_slot, uint64_t target_memory, double target_time, bool is_decoy){
	Data data;
	uint8_t master_key[HASHLEN];
	size_t start_sector, end_sector;
	
	decide_start_and_end_sector(device, is_decoy, &start_sector, &end_sector);
	initialize_new_header(&data, enc_type, start_sector, end_sector);
	add_key_from_decrypted_data_using_master_key(&data, master_key, key, target_slot, target_memory, target_time);
	operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask);
	if (is_decoy){
		create_fat32_on_device(device);
	}
	
	write_header_to_device(&data, device, is_decoy ? -(int64_t)sizeof(Data) : 0);
}

int action_open(const char * device, const char * target_name, const Key * key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double
max_unlock_time, bool is_target_readonly, bool is_dry_run, bool is_decoy){
	
	OPERATION_BACKEND_UNLOCK
	
	if (!is_dry_run){
		uint8_t disk_key[HASHLEN];
		get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, disk_key);
		create_crypt_mapping_from_disk_key(device, target_name, data.metadata, disk_key,  is_target_readonly);
	}
	return unlocked_slot;
}

void action_close(const char * device){
	remove_crypt_mapping(device);
}

int action_addkey(const char * device, const Key * key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double max_unlock_time, int target_slot,
						 uint64_t target_memory,
						 double target_time, bool is_decoy){
	
	OPERATION_BACKEND_UNLOCK
	
	Key new_key;
	interactive_ask_new_key(&new_key);
	int added_slot = add_key_from_decrypted_data_using_master_key(&data, master_key, new_key, target_slot, target_memory, target_time);
	
	operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask);
	write_header_to_device(&data, device, offset);
	return added_slot;
}

void action_create_format(const char * device, bool is_decoy){
	READ_HEADER
	
	fill_secure_random_bits(data.master_key_mask, HASHLEN);
	write_header_to_device(&data, device, offset);
}

int action_revokekey(const char * device, const Key * key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double max_unlock_time,
							bool is_revoke_all, bool is_obliterate, bool is_decoy){
	
	if (is_revoke_all){
		READ_HEADER
		for (int i = 0; i < KEY_SLOT_COUNT; i++){
			revoke_given_key_slot(&data, i, false);
		}
		write_header_to_device(&data, device, offset);
		return -1;
	} else if (is_obliterate){
		READ_HEADER
		for (int i = 0 ; i < 3; i++) {
			fill_secure_random_bits((uint8_t *) &data, sizeof(Data));
			write_header_to_device(&data, device, offset);
		}
		return -1;
	}
	
	else if (target_unlock_slot != -1){
		READ_HEADER
		revoke_given_key_slot(&data, target_unlock_slot, false);
		write_header_to_device(&data, device, offset);
		return target_unlock_slot;
	}
	
	
	OPERATION_BACKEND_UNLOCK

	revoke_given_key_slot(&data, unlocked_slot, true);
	operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask);
	
	write_header_to_device(&data, device, offset);
	return unlocked_slot;
}

void init(){
	init_random_generator("/dev/urandom");
	get_system_info();
}
