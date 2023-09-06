//
// Created by level-128 on 9/1/23.
//

#include "../mapper.c"



void test_map_device(){
	const char *device = "/dev/loop0";
	const char *name = "my_crypt_device";
	const char *enc_type = "serpent-cbc-essiv:sha256";
	const char *password = "cc6267b0ec9e80cbb77da3320f12c5441d3fe8b086528c4b55cb8fd6c3710363";
	
	create_crypt_mapping(device, name, enc_type, password);
//	get_device_size("/dev/mapper/my_crypt_device");
	remove_crypt_mapping(name);
}

void test_create_password() {
	uint8_t masterkey[HASHLEN];
	
	uint8_t master_key[HASHLEN];
	char key[HASHLEN * 2];
	fill_secure_random_bits(masterkey, HASHLEN);
	create_password(masterkey, key);
	print(key);
}

int test_mapper() {
	test_map_device();
}