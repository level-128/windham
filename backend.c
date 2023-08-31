//
// Created by level-128 on 8/24/23.
//

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include "sha256.h"

struct SystemInfo {
	unsigned long free_ram;
	unsigned long total_swap;
	unsigned long free_swap;
	long num_processors;
};


typedef struct {
	char * key_or_keyfile_location;
	uint32_t key_len;
	uint32_t key_type;
} Key;

enum {
	EMOBJ_key_file_type_input,
	EMOBJ_key_file_type_key,
	EMOBJ_key_file_type_file
};


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

uint8_t * read_key_file(const Key * key, size_t * length) {
	char * filename = key->key_or_keyfile_location;
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



void init_key(const Key * key, uint8_t inited_key[HASHLEN]) {
	size_t key_size;
	if (key->key_type == EMOBJ_key_file_type_file) {
		uint8_t * key_buffer = read_key_file(key, &key_size);
		sha256_digest_all(key_buffer, key_size, inited_key);
		free(key_buffer);
	} else {
		sha256_digest_all(key->key_or_keyfile_location, key->key_len, inited_key);
	}
	if (key->key_type == EMOBJ_key_file_type_input) {
		free(key->key_or_keyfile_location);
	}
}

uint64_t calc_initial_pw_hash_and_iter_cnt(Data * self, uint8_t * inited_key, int target_slot, uint64_t max_mem_size, double time_limit, uint8_t
password_hash[KEY_SLOT_COUNT][HASHLEN]) {
	// password hash is password_hash[KEY_SLOT_COUNT][HASHLEN] if target_slot == -1, else use &password_hash[HASHLEN]
	
	double time_cost = 0;
	
	if (target_slot == -1) { // all slots
		// initial hash and benchmarking
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			Key_slot * key_slot = &self->keys[i];
			time_cost += hash_firstpass_and_benchmark(key_slot, inited_key, password_hash[i]);
		}
		time_cost /= 4;
	} else {
		time_cost = hash_firstpass_and_benchmark(&self->keys[target_slot], inited_key, password_hash[0]);
	}
	
	if (time_limit != 0) {
		if (time_limit / time_cost * BASE_MEM_COST * 2 < (double) max_mem_size || max_mem_size == 0) {
			max_mem_size = (uint64_t) (time_limit / time_cost * BASE_MEM_COST * 2);
		}
	}
	return max_mem_size;
}

void get_master_key(Data * self, uint8_t master_key[HASHLEN], const Key * key, int target_slot, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t password_hash[KEY_SLOT_COUNT][HASHLEN]; // calculating hash in password_hash
	uint8_t inited_key[HASHLEN];
	init_key(key, inited_key);
	
	uint64_t mem_size_limit = calc_initial_pw_hash_and_iter_cnt(self, inited_key, target_slot, max_unlock_mem, max_unlock_time, password_hash);
	
	// TODO create threads to unlock the drive
	
	if (target_slot != -1){
		if (get_master_key_from_slot(&self->keys[target_slot], password_hash[0], mem_size_limit, master_key)){
			return;
		}
	} else {
		
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			if (get_master_key_from_slot(&self->keys[i], password_hash[i], mem_size_limit, master_key)) {
				return;
			}
		}
	}
	print_error("Cannot unlock the target because time or memory limit has reached. This is probably because a wrong key\n"
					"have been provided, or your compute resources may be too insufficient to unlock the target created\n"
					"by high-performance devices. If the latter is correct, then consider increasing the maximum runtime\n"
					"limit (which will result in using more memory). If the operation cannot be completed due to lack of\n"
					"memory, consider exporting the master key on a more computationally powerful device and then use the\n"
					"master key to unlock the target.");

}



void add_key_from_master_key(Data * self, const uint8_t master_key[HASHLEN], const Key * key, uint64_t max_unlock_mem, double max_unlock_time) {
	uint8_t password_hash[HASHLEN];
	uint8_t inited_key[HASHLEN];
	
	operate_metadata_using_master_key(&self->metadata, master_key, self->master_key_mask, true);
	int target_slot = -1;
	for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--){
		if (self->metadata.key_slot_usage[i] == Key_slot_unused){
			target_slot = i;
		}
	}
	if (target_slot == -1){
		for (int i = KEY_SLOT_COUNT - 1; i >= 0; i--){
			if (self->metadata.key_slot_usage[i] == Key_slot_revoked){
				target_slot = i;
			}
		}
	}
	if (target_slot == -1){
		print_error("No free slots. Remove a key first.");
	}
	self->metadata.key_slot_usage[target_slot] = Key_slot_used;
	operate_metadata_using_master_key(&self->metadata, master_key, self->master_key_mask, false);
	
	init_key(key, inited_key);
	
	uint64_t mem_size_limit = calc_initial_pw_hash_and_iter_cnt(self, inited_key, target_slot, max_unlock_mem, max_unlock_time, &password_hash);
	set_master_key_to_slot(&self->keys[target_slot], password_hash, mem_size_limit, master_key);
	
}

void create_header_and_master_key(Data * self, uint8_t master_key[HASHLEN], const char * enc_type){
	fill_secure_random_bits(self, sizeof(Data));
	memset(self->metadata.key_slot_usage, Key_slot_unused, sizeof(self->metadata.key_slot_usage));
	if (enc_type != NULL){
		strcpy(self->metadata.enc_type, enc_type);
	} else {
		strcpy(self->metadata.enc_type, DEFAULT_DISK_ENC_MODE);
	}
	operate_metadata_using_master_key(&self->metadata, master_key, self->master_key_mask, false);
	
}