//
// Created by level-128 on 8/31/23.
//

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
	memcpy(master_key, (void *)"012345678901234567890123456789012", strlen("012345678901234567890123456789012") - 1);
	
	// initialize header
	Data header;
	initialize_new_header(&header, NULL, 0, 4000);
	
	
	// test unlock
	int slot = add_key(&header, master_key, key1, 0, 100000, -1);
	assert(memcmp(header.metadata.all_key_mask[slot], header.keys[slot].key_mask, HASHLEN) == 0);
	assert(memcmp(header.metadata.inited_key[slot], inited_key, HASHLEN) == 0);
	assert(slot == 0);

	slot = add_key(&header, master_key, key2, 2, 100000, -1);
	assert(memcmp(header.metadata.all_key_mask[slot], header.keys[slot].key_mask, HASHLEN) == 0);
	assert(slot == 2);
	
	slot = add_key(&header, master_key, key3, 2, 100000, -1);
	assert(slot != 2); // slot should not be the same, since slot 2 has been occupied by key2.
	
	
	// error should pop up when add existing key
	debug_print_error_suppress = true;
	add_key(&header, master_key, key3, -1, 100000, -1);
	assert(debug_print_error_suppress == false);
	
	// lock all keyslots. Keyslots should be locked before metadata
	operate_all_keyslots(header.keys, header.metadata.inited_key, header.master_key_mask, false);
	
	// lock the metadata
	assert(operate_metadata_using_master_key(&header.metadata, master_key, header.master_key_mask));
	
	// check unlock
	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key1, -1, 200000, -1);
	assert(memcmp(master_key, "012345678901234567890123456789012", HASHLEN) == 0);

	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key3, -1, 200000, -1);
	assert(memcmp(master_key, "012345678901234567890123456789012", HASHLEN) == 0);

	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key2, -1, 200000, -1);
	assert(memcmp(master_key, "012345678901234567890123456789012", HASHLEN) == 0);
}

void test_create_open_chain(char * device_){
	is_running_as_root();
	
	Key key1, key2;
	key1.key_or_keyfile_location = "hello world1";
	key1.key_type = EMOBJ_key_file_type_key;
	
	key2.key_or_keyfile_location = "hello world2";
	key2.key_type = EMOBJ_key_file_type_key;
	
	uint8_t master_key[HASHLEN];
	

	action_create(device_, NULL, key1, -1, 10000, -1, false);
	action_open(device_, "my_crypt_device", key1, master_key, -1, 30000, -1, false, false, false);
	
	action_close("my_crypt_device");
	action_addkey(device_, key1, master_key, -1, 20000, 0, 3, 0, 1, false);
	action_open(device_, "my_crypt_device", key2, master_key, -1, 0, 3, false, false, false);
	action_close("my_crypt_device");
	action_revokekey(device_, key2, master_key, -1, 0, 3, false, false, false);
	
	debug_print_error_suppress = true;
	action_open(device_, "my_crypt_device", key2, master_key, -1, 0, 3, false, false, false);
	assert(debug_print_error_suppress == false);
}

void test_backend(__attribute__((unused)) char * device){
//	ask_for_conformation("hello world");
	test_backend_add_key_and_get_key();
//	test_create_open_chain(device);
}
