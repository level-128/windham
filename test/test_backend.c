//
// Created by level-128 on 8/31/23.
//

#include <float.h>
#include "../backend.c"

void test_backend_add_key_and_get_key(){
	
	// Create 3 keys
	Key key1, key2, key3;

	key1.key_or_keyfile_location = "hello world1";
	key1.key_type = EMOBJ_key_file_type_key;
	uint8_t inited_key[HASHLEN];
	init_key(key1, inited_key);

	key2.key_or_keyfile_location = "hello world2";
	key2.key_type = EMOBJ_key_file_type_key;

	key3.key_or_keyfile_location = "hello world3";
	key3.key_type = EMOBJ_key_file_type_key;

	
	// set master key
	uint8_t master_key[HASHLEN];
	memcpy(master_key, (void *)"01234567890123456789012345678901", strlen("01234567890123456789012345678901"));
	
	// initialize header
	Data header;
	initialize_new_header(&header, DEFAULT_DISK_ENC_MODE, 0, 4000, 4096);
	
	
	// test addkey
	int slot = add_key_to_keyslot(&header, master_key, key1, 0, 100000, 1);
	
	// test is correct slot
	assert(slot == 0);
	
	// test header.metadata.all_key_mask[slot] matchs
	assert(memcmp(header.metadata.all_key_mask[slot], header.keyslots[slot].key_mask, HASHLEN) == 0);
	
	// test is keyslot_key registers
	uint8_t keyslot_key1[HASHLEN];
	get_keyslot_key_from_inited_key(inited_key, header.uuid_and_salt, keyslot_key1);
	assert(memcmp(header.metadata.keyslot_key[slot], keyslot_key1, HASHLEN) == 0);

	// addkey2
	slot = add_key_to_keyslot(&header, master_key, key2, 2, 100000, 1);
	assert(memcmp(header.metadata.all_key_mask[slot], header.keyslots[slot].key_mask, HASHLEN) == 0);
	assert(slot == 2);
	
	// addkey3
	slot = add_key_to_keyslot(&header, master_key, key3, 2, 100000, 1);
	assert(slot != 2); // slot should not be the same, since slot 2 has been occupied by key2.
	
	
	// error should pop up when add existing key
	debug_print_error_suppress = 1;
	add_key_to_keyslot(&header, master_key, key3, -1, 100000, 1);
	assert(debug_print_error_suppress == 0);
	
	// lock all keyslots. Keyslots should be locked before metadata
	operate_all_keyslots_using_keyslot_key_in_metadata(header.keyslots, header.metadata.keyslot_key, header.master_key_mask, false);
	
	// lock the metadata
	assert(lock_or_unlock_metadata_using_master_key(&header, master_key));
	
	// check unlock
	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key1, -1, 200000, 3);
	assert(memcmp(master_key, "01234567890123456789012345678901", HASHLEN) == 0);

	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key3, -1, 200000, 3);
	assert(memcmp(master_key, "01234567890123456789012345678901", HASHLEN) == 0);

	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key2, -1, 200000, 3);
	assert(memcmp(master_key, "01234567890123456789012345678901", HASHLEN) == 0);
}

void test_create_open_chain(char * device_){
	is_running_as_root();
	
	Key key1, key2;
	key1.key_or_keyfile_location = "hello world1";
	key1.key_type = EMOBJ_key_file_type_key;
	
	key2.key_or_keyfile_location = "hello world2";
	key2.key_type = EMOBJ_key_file_type_key;
	
	uint8_t master_key[HASHLEN];
	
	is_skip_conformation = true;
	print_enable = true;
	
	action_create(device_, "aes-xts-plain64", key1, 3, 0, 1.5, false, DEFAULT_BLOCK_SIZE);
	action_open(device_, "my_crypt_device", key1, master_key, 3, 0, 3, false, 0, false, false, true, false, false);
	
	action_close("my_crypt_device");
	
	
	interactive_ask_new_key_test_key = "hello world2";
	action_addkey(device_, key1, master_key, 3, 0, 3, 3, 0, 1, false);
	action_open(device_, "my_crypt_device", key2, master_key, -1, 0, 3, false, 0, false, false, false, true, false);
	action_close("my_crypt_device");
	action_revokekey(device_, key2, master_key, -1, 0, 3, false, false, false);
	
	action_suspend(device_, key1, master_key, -1, 0, 3, false);
	
	assert(action_open_suspended_or_keyring(device_, "my_crypt_device", false, false, false, false, false, false) == true);
	action_close("my_crypt_device");
	action_resume(device_, key1, master_key, -1, 0, 3, false);
	
//	debug_print_error_suppress = 2;
//	action_open(device_, "my_crypt_device", key2, master_key, -1, 0, 3, false, false, false, false, true, false);
//	assert(debug_print_error_suppress == 0);
	
}

void test_backend(__attribute__((unused)) char * device){
	
	print("test_create_open_chain");
	test_create_open_chain(device);
	test_backend_add_key_and_get_key();
}
