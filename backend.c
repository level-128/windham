//
// Created by level-128 on 8/24/23.
//

#include <sys/sysinfo.h>
#include <sys/stat.h>

#define MAX_KEY_CHAR 512



#include "sha256.h"
#include "mapper.c"

struct SystemInfo {
	unsigned long free_ram;
	unsigned long total_swap;
	unsigned long free_swap;
	long num_processors;
};


typedef struct {
	char * key_or_keyfile_location;
	uint32_t key_type;
} Key;

enum {
	EMOBJ_key_file_type_input,
	EMOBJ_key_file_type_key,
	EMOBJ_key_file_type_file
};

void print_hex_array(const uint8_t * arr, size_t length) {
	for (size_t i = 0; i < length; ++i) {
		printf("%02x ", arr[i]);
	}
	printf("\n");
}



void is_running_as_root() {
	if (getuid() != 0) {
		print_error("The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible without root permission");
	}
}

struct SystemInfo get_system_info() {
	struct sysinfo info;
	struct SystemInfo sys_info;
	
	
	if (sysinfo(&info) == -1) {
		perror("sysinfo");
		exit(EXIT_FAILURE);
	}
	
	
	long num_processors = sysconf(_SC_NPROCESSORS_ONLN);
	if (num_processors == -1) {
		perror("sysconf");
		exit(EXIT_FAILURE);
	}
	
	sys_info.free_ram = info.freeram / 1024;
	sys_info.total_swap = info.totalswap;
	sys_info.free_swap = info.freeswap;
	sys_info.num_processors = num_processors;
	
	return sys_info;
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


char* get_input() {
	int size = 20;
	char *input = (char *) malloc(size * sizeof(char));
	char ch;
	int index = 0;
	
	while (1) {
		ch = getchar();
		
		if (ch == '\n') {
			break;
		}
		input[index++] = ch;
		
		if (index == size) {
			size += 20;
			input = (char *) realloc(input, size * sizeof(char));
		}
	}
	input[index] = '\0';
	return input;
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

void check_iter_count(uint64_t ){
	// TODO
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
	
	// TODO create threads to unlock the drive
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
					"have been provided, or your compute resources may be too insufficient to unlock the target created\n"
					"by high-performance devices. If the latter is correct, then consider increasing the maximum runtime\n"
					"limit (which will result in using more memory). If the operation cannot be completed due to lack of\n"
					"memory, consider exporting the master key on a more computationally powerful device and then use the\n"
					"master key to unlock the target.");

}


void add_key_from_decrypted_data_using_master_key(Data * decrypted_self, const uint8_t master_key[32], const Key key, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t password_hash[HASHLEN];
	uint8_t inited_key[HASHLEN];
	
	init_key(key, inited_key);
	
	int target_slot = select_available_key_slot(decrypted_self->metadata, decrypted_self->keys);
	if (target_slot == -1) {
		print_error("All key slots are full. Remove or revoke one or more keys to add new key.");
	}
	register_key_slot_as_used(&decrypted_self->metadata, decrypted_self->keys, target_slot);
	
	uint64_t mem_size_limit = calc_initial_pw_hash_and_iter_cnt(decrypted_self, inited_key, target_slot, max_unlock_mem, max_unlock_time, NULL, password_hash);

	set_master_key_to_slot(&decrypted_self->keys[target_slot], password_hash, mem_size_limit, master_key);
}


void action_create(const char * device, const char * enc_type, const Key key, uint64_t max_unlock_mem, double max_unlock_time){
	Data data;
	uint8_t master_key[HASHLEN];
	
	fill_secure_random_bits(master_key, HASHLEN);
	initialize_unlock_header_and_master_key(&data, master_key, enc_type, sizeof(Data));
	add_key_from_decrypted_data_using_master_key(&data, master_key, key, max_unlock_mem, max_unlock_time);
	operate_metadata_using_master_key(&data.metadata, master_key, data.master_key_mask, false);
	write_header_to_device(&data, device);
}

void action_open(const char * device, const char * target_name, const Key * key, const uint8_t master_key[32], int target_slot, uint64_t max_unlock_mem, double
max_unlock_time, bool is_dry_run, bool is_target_readonly){

	uint8_t master_key_ [HASHLEN];
	Data data;
	uint8_t disk_key[HASHLEN];
	get_header_from_device(&data, device);
	
	if (key != NULL){
		get_master_key(data, master_key_, *key, target_slot, max_unlock_mem, max_unlock_time);
	} else {
		memcpy(master_key_, master_key, HASHLEN);
	}
	operate_metadata_using_master_key(&data.metadata, master_key_, data.master_key_mask, true);
	if (data.metadata.check_key_magic_number != CHECK_KEY_MAGIC_NUMBER) {
		if (key != NULL){print_error("This key has been revoked. ");}
		else {print_error("Wrong master key.");}
	}
	
	get_metadata_key_and_disk_key_from_master_key(master_key_, data.master_key_mask, NULL, disk_key);
	if (! is_dry_run){
		create_crypt_mapping_from_disk_key(device, target_name, data.metadata.enc_type, disk_key, data.metadata.payload_offset, is_target_readonly);
	} else {
		print("Dry run complete. Disk key:");
		
	}
}

void action_close(const char * device){
	remove_crypt_mapping(device);
}