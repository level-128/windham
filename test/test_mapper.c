//
// Created by level-128 on 9/1/23.
//

#include "../mapper.c"



void test_map_device(){
	const char *device = "/dev/sdb";
	const char *name = "my_crypt_device1";
	const char *enc_type = "serpent-cbc-essiv:sha256";
	const char *password = "cc6267b0ec9e80cbb77da3320f12c5441d3fe8b086528c4b55cb8fd6c3710363";
	
	
	create_crypt_mapping(device, name, enc_type, password, 1300, false);
//	get_device_sector_cnt("/dev/mapper/my_crypt_device");
	remove_crypt_mapping(name);
}

void test_create_password() {
	uint8_t masterkey[HASHLEN];
	
	uint8_t master_key[HASHLEN];
	char key[HASHLEN * 2 + 1];
	fill_secure_random_bits(masterkey, HASHLEN);
	convert_password_from_disk_key(masterkey, key);
	print(key);
}

int test_mapper() {
	test_map_device();
}