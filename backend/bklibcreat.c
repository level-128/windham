//
// Created by level-128 on 1/19/24.
//

#include "bklibkey.c"
#include "bksrclib.c"
#include "../library_intrnlsrc/mapper.c"

#define MAX_LINE_LENGTH 1024
#define TARGET_PREFIX "name         : "

char ** get_crypto_list() {
	int crypto_count = 0;
	FILE * file;
	char line[MAX_LINE_LENGTH];
	char ** crypto_list = NULL;
	
	file = fopen("/proc/crypto", "r");
	if (file == NULL) {
		print_warning(_("Cannot determine available encryption mode on the system. Please ensure that the kernel encryption subsystem is available."));
		return NULL;
	}
	
	while (fgets(line, sizeof(line), file)) {
		if (strncmp(line, TARGET_PREFIX, strlen(TARGET_PREFIX)) == 0) {
			char * name = line + strlen(TARGET_PREFIX);
			if (*name != '_' && strcmp("stdrng\n", name) != 0) {
				(crypto_count)++;
				crypto_list = realloc(crypto_list, sizeof(char *) * crypto_count);
				
				crypto_list[crypto_count - 1] = strdup(name);
				
				char * end = crypto_list[crypto_count - 1] + strlen(crypto_list[crypto_count - 1]) - 1;
				if (*end == '\n') {
					*end = '\0';
				}
			}
		}
	}
	crypto_list = realloc(crypto_list, sizeof(char *) * (crypto_count + 1));
	crypto_list[crypto_count] = NULL;
	fclose(file);
	return crypto_list;
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

void action_create(const char * device, const char * enc_type, const Key key, int target_slot, size_t target_memory, double target_time, size_t block_size, size_t section_size, bool is_decoy,
                   bool is_dyn_enc, bool is_no_fail){
	check_file(device, true, is_no_fail);
	check_is_device_mounted(device);
	
	enc_type = enc_type ? enc_type : DEFAULT_DISK_ENC_MODE;
	action_new_check_crypt_support_status(enc_type);
	
	Data data; uint8_t master_key[HASHLEN]; size_t start_sector, end_sector;
	fill_secure_random_bits(master_key, HASHLEN);
	size_t block_count = decide_start_and_end_block_ret_blkcnt(device, &start_sector, &end_sector, block_size, section_size, is_decoy, is_dyn_enc);
	initialize_new_header(&data, enc_type, start_sector, end_sector, block_size);
	add_key_to_keyslot(&data, master_key, key, device, target_slot, target_memory, target_time);
	
	if (is_dyn_enc){
		Dynenc_param dynenc_param;
		uint8_t disk_key[HASHLEN];
		
		dynesc_calc_param(&dynenc_param, block_count, section_size);
		
		shrink_disk(dynenc_param, device);
		
		get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, data.uuid_and_salt, disk_key);
		create_crypt_mapping_from_disk_key(device, ".tmp_windham", &data.metadata, disk_key, data.uuid_and_salt, false, false, true, true, true);
		
		tag_header_as_converting(&data, section_size);
		int64_t offset = -4096;
		OPERATION_LOCK_AND_WRITE
		
		create_disk_hash(dynenc_param, device);
		
		if (copy_disk(dynenc_param, device, "/dev/mapper/.tmp_windham", UINT64_MAX) == false) {
			remove_crypt_mapping(".tmp_windham");
			exit(EXIT_FAILURE);
		};
		
		untag_header_as_converting(&data);
		write_header_to_device(&data, device, 0);
		
		remove_crypt_mapping(".tmp_windham");
	} else {
		ask_for_conformation(_("Creating encrypt partition on device: %s, All content will be lost. Continue?"), device);
		
		int64_t offset = is_decoy ? -4096 : 0;
		OPERATION_LOCK_AND_WRITE
		
		if (is_decoy) {
			create_fat32_on_device(device);
		}
	}
};