//
// Created by level-128 on 9/1/23.
//
void test_map_device(char * device_) {
	print("test_map_device");
	const char * name = "my_crypt_device1_test";
	const char * enc_type = "serpent-cbc-essiv:sha256";
	const char * password = "cc6267b0ec9e80cbb77da3320f12c5441d3fe8b086528c4b55cb8fd6c3710363";
	
	size_t start_sector, end_sector;
	decide_start_and_end_sector(device_, false, &start_sector, &end_sector, 4096);
	
	print("device start and end sector:", start_sector, end_sector, "size :", end_sector - start_sector);
	
	create_crypt_mapping(device_, name, enc_type, password, "12345678-1234-1234-1234-123456789abc", start_sector, end_sector, 4096, false, true, false, false);
	
	remove_crypt_mapping(name);
}

void test_create_password() {
	uint8_t masterkey[HASHLEN];
	
	char key[HASHLEN * 2 + 1];
	fill_secure_random_bits(masterkey, HASHLEN);
	convert_disk_key_to_hex_format(masterkey, key);
	print(key);
}

void test_fat32(char * device_) {
	print(detect_fat32_on_device(device_));
	
}

void test_is_device_mounted(char * device_) {
	check_is_device_mounted(device_);
}

int test_mapper(char * device_) {
	print("test mapper");
	test_is_device_mounted(device_);
	test_map_device(device_);
	test_fat32(device_);
	return 0;
}