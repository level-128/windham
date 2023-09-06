//
// Created by level-128 on 8/24/23.
//

#include <sys/sysinfo.h>
#include <sys/stat.h>

#define MAX_KEY_CHAR 512



#include "sha256.h"

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
	
	
	if (file_size < 4096) {
		print_error("block device is less than 4 KiB");
	}
}



void get_key_input_from_the_console(char key_buffer[MAX_KEY_CHAR]){
	char verify_buffer[MAX_KEY_CHAR];
	memset(key_buffer, 0, MAX_KEY_CHAR);
	memset(verify_buffer, 0, MAX_KEY_CHAR);
	print("key:");
	fgets(key_buffer, MAX_KEY_CHAR, stdin);
	print("Again:");
	fgets(verify_buffer, MAX_KEY_CHAR, stdin);
	if (memcmp(key_buffer, verify_buffer, MAX_KEY_CHAR)){
		print_error("Passwords do not match.");
	}
	
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

uint64_t calc_initial_pw_hash_and_iter_cnt(Data * self, uint8_t * inited_key, int target_slot, uint64_t max_mem_size, double time_limit, uint8_t
password_hash_all_slots[KEY_SLOT_COUNT][HASHLEN], uint8_t password_hash[HASHLEN]) {
	// password hash is password_hash_all_slots[KEY_SLOT_COUNT][HASHLEN] if target_slot == -1, else use &password_hash_all_slots[HASHLEN]
	double time_cost = 0;
	
	if (target_slot == -1) { // all slots
		// initial hash and benchmarking
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			Key_slot * key_slot = &self->keys[i];
			time_cost += hash_firstpass_and_benchmark(key_slot, inited_key, password_hash_all_slots[i]);
		}
		time_cost /= 4;
	} else {
		time_cost = hash_firstpass_and_benchmark(&self->keys[target_slot], inited_key, password_hash);
	}
	
	if (time_limit > 0) {
		if (time_limit / time_cost * BASE_MEM_COST * 2 < (double) max_mem_size || max_mem_size == 0) {
			max_mem_size = (uint64_t) (time_limit / time_cost * BASE_MEM_COST * 2);
		}
	}
	return max_mem_size;
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
		if (! operate_metadata_using_master_key(&self.metadata, master_key, self.master_key_mask, true)){
			print_error("This key has been revoked. ");
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


void add_key_using_master_key(Data * decrypted_self, const uint8_t master_key[HASHLEN], const Key key, uint64_t max_unlock_mem, double max_unlock_time) {
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

void revoke_key_using_master_key(Data * decrypted_self, const uint8_t master_key[HASHLEN]){
	int active_key_slot_count = 0;
	for (int i = 0; i < KEY_SLOT_COUNT; i++){
		if (decrypted_self->metadata.key_slot_is_used)
	}
}