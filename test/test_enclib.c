//
// Created by level-128 on 8/31/23.
//

#include <memory.h>
#include <malloc.h>
#include "assert.h"
#include "../print.c"
#include "../enclib.c"

Data my_data;
uint8_t password_set[HASHLEN];

void test_set_get_master_key(){

	uint8_t masterkey[HASHLEN];
	
	strcpy((char *) password_set, "hello world!"); // "hello world!" plus random uninitialized memory
	set_master_key_to_slot(&my_data.keys[0], password_set, 15000, (uint8_t *) "a master key example.          ");
	
	fill_secure_random_bits(masterkey, HASHLEN);

	get_master_key_from_slot(&my_data.keys[0], password_set, 20000, masterkey);
	assert(strcmp((char *) masterkey, "a master key example.          ") == 0);
	print("test_set_get_master_key Done");
	
};

void test_rand_gen(){
	uint8_t data[100];
	fill_secure_random_bits(data, 100);
//	print_hex_array(data, 100);
}

void test_metadata(){
	uint8_t masterkey[HASHLEN];
	strcpy(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE);
	operate_metadata_using_master_key(&my_data.metadata, masterkey, my_data.master_key_mask, false);
	assert(strcmp(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE) != 0);
	operate_metadata_using_master_key(&my_data.metadata, masterkey, my_data.master_key_mask, true);
	assert(strcmp(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE) == 0);
	
}

void test_enclib(){
	test_rand_gen();

	fill_secure_random_bits((uint8_t *)&my_data, sizeof(my_data));
	
	test_set_get_master_key();
	test_metadata();
	
}