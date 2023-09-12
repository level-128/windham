//
// Created by level-128 on 8/31/23.
//

#include "../backend.c"

void test_backend_add_key_and_get_key(){
	Data header;

	Key key1, key2, key3;
	
	key1.key_or_keyfile_location = "hello world1";
	key1.key_type = EMOBJ_key_file_type_key;
	
	key2.key_or_keyfile_location = "hello world2";
	key2.key_type = EMOBJ_key_file_type_key;
	
	key3.key_or_keyfile_location = "hello world3";
	key3.key_type = EMOBJ_key_file_type_key;
	
	uint8_t master_key[HASHLEN];
	memcpy(master_key, "012345678901234567890123456789012", strlen("012345678901234567890123456789012") - 1);
	
	initialize_unlock_header_and_master_key(&header, master_key, NULL, 0);
	
	add_key_from_decrypted_data_using_master_key(&header, master_key, key1, 100000, -1);
	
	add_key_from_decrypted_data_using_master_key(&header, master_key, key2, 100000, -1);
	
	add_key_from_decrypted_data_using_master_key(&header, master_key, key3, 100000, -1);
	
	operate_metadata_using_master_key(&header.metadata, master_key, header.master_key_mask, false);
	
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

void test_create_open_chain(){
	is_running_as_root();
	Key key;
	key.key_or_keyfile_location = "hello world1";
	key.key_type = EMOBJ_key_file_type_key;
	uint8_t master_key[HASHLEN];
	
	char * device = "/dev/sdb";
	action_close("/dev/dm-2");
	return;
	action_create(device, NULL, key, 10000, -1);
	action_open(device, "my_crypt_device", &key, master_key, -1, 30000, -1, false, false);
}

void test_backend(){
//	ask_for_conformation("hello world");
//	test_backend_add_key_and_get_key();
	test_create_open_chain();
}
