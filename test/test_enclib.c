//
// Created by level-128 on 8/31/23.
//

#include <memory.h>
#include <malloc.h>
#include "assert.h"
#include "../print.c"
#include "../enclib.c"

Data my_data;
uint8_t password_set[HASHLEN], masterkey[HASHLEN];

void test_set_get_master_key(){


	strcpy(password_set, "hello world!"); // "hello world!" plus random uninitialized memory
	set_master_key_to_slot(&my_data.keys[0], password_set, 4000, (uint8_t *) "a master key example. ");
	

	get_master_key_from_slot(&my_data.keys[0], password_set, 20000, masterkey);
	assert(strcmp(masterkey, "a master key example. ") == 0);
	
};

void test_rand_gen(){
	uint8_t data[100];
	fill_secure_random_bits(data, 100);
//	print_hex_array(data, 100);
}

void test_metadata(){
	strcpy(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE);
	operate_metadata_using_master_key(&my_data.metadata, masterkey, my_data.master_key_mask, false);
	assert(strcmp(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE) != 0);
	operate_metadata_using_master_key(&my_data.metadata, masterkey, my_data.master_key_mask, true);
	assert(strcmp(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE) == 0);
	
}

void test_enclib(){
	test_rand_gen();

	fill_secure_random_bits(&my_data, sizeof(my_data));
	
	test_set_get_master_key();
	test_metadata();
	
}