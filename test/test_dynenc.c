#include "windham_const.h"

void test_dynenc_(char * device_){

//	write_test(device_);

	Key key1;
	key1.key_or_keyfile_location = "hello world";
	key1.key_type = EMOBJ_key_file_type_key;

//	action_close(".tmp_windham");

	action_create_convert(device_, DEFAULT_DISK_ENC_MODE, key1, -1, 0, 1, 4096, 4096 * 1024);
	
}



int test_dynenc(char * device_) {
	is_skip_conformation = true;
	print("test dynenc");
	test_dynenc_(device_);
	return 0;
}