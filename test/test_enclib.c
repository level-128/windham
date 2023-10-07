//
// Created by level-128 on 8/31/23.
//

#include <memory.h>
#include <malloc.h>
#include "assert.h"
#include "../print.c"
#include "../enclib.c"




void test_set_get_master_key(){
	Data my_data;
	fill_secure_random_bits((uint8_t *)&my_data, sizeof(my_data));

	uint8_t masterkey[HASHLEN]  = {'h', 'e', 'l', 'l', 'o'};;
	uint8_t password_set[HASHLEN];
	
	strcpy((char *) password_set, "hello world!"); // "hello world!" plus random uninitialized memory
	set_master_key_to_slot(&my_data.keys[0], password_set, 15000, (uint8_t *) "a master key example.          ");
	
	fill_secure_random_bits(masterkey, HASHLEN);

	get_master_key_from_slot(&my_data.keys[0], password_set, 20000, masterkey);
	assert(strcmp((char *) masterkey, "a master key example.          ") == 0);
	
};

void test_metadata(){
	Data my_data;
	
	uint8_t masterkey[HASHLEN] = {'h', 'e', 'l', 'l', 'o'};
	strcpy(my_data.metadata.enc_type, DEFAULT_DISK_ENC_MODE);
	fill_secure_random_bits((uint8_t *) &my_data, sizeof(Data));
	my_data.metadata.check_key_magic_number = CHECK_KEY_MAGIC_NUMBER;
	assert(operate_metadata_using_master_key(&my_data.metadata, masterkey, my_data.master_key_mask));

	assert(operate_metadata_using_master_key(&my_data.metadata, masterkey, my_data.master_key_mask));

	
}

void test_enclib(){
	
	test_set_get_master_key();
	test_metadata();
	
}