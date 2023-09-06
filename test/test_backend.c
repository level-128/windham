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
	
	initialize_header_and_master_key(&header, master_key, NULL);
	
	add_key_using_master_key(&header, master_key, key1, 10000, -1);

	add_key_using_master_key(&header, master_key, key2, 10000, -1);

	add_key_using_master_key(&header, master_key, key3, 10000, -1);
	
	finalize_header_and_master_key(&header, master_key);
	
	fill_secure_random_bits(master_key, HASHLEN);

	get_master_key(header, master_key, key1, -1, 15000, -1);
	assert(memcmp(master_key, "012345678901234567890123456789012", HASHLEN) == 0);
	
	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key3, -1, 30000, -1);
	assert(memcmp(master_key, "012345678901234567890123456789012", HASHLEN) == 0);

	fill_secure_random_bits(master_key, HASHLEN);
	get_master_key(header, master_key, key2, -1, 30000, -1);
	assert(memcmp(master_key, "012345678901234567890123456789012", HASHLEN) == 0);
	
}

void test_revoke_key(){

}

void test_backend(){
	test_backend_add_key_and_get_key();
}
