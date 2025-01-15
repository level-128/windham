//
// Created by level-128 on 8/31/23.
//

#include "testutil.c"


void test_basic_open_and_close(char * device_) {
	exec_test_command("New % --key=123 --target-time=0.1");
	interactive_ask_new_key_test_key = "1234";
	// exec_test_command("AddKey % --key=123 ");
	exec_test_command("Open % --key=123 --to=enc1 --verbose --max-unlock-time=1");
	exec_test_command("Close enc1");
	// exec_test_command("Open % --key=1234 --to=enc1 --verbose --max-unlock-time=2");
	// exec_test_command("Close enc1");
	// exec_test_command("Open % --key=1234 --to=enc1 --verbose --max-unlock-time=1");
	// exec_test_command("Open % --key=123 --to=enc1 --unlock-slot=1 --max-unlock-time=-");
	// exec_test_command("Close enc1");
}


void test_create_open_chain(char * device_) {
	exec_test_command("New % --key=123");
	exec_test_command("Suspend % --key=123");
	exec_test_command("Open % --key=123 --dry-run");
	exec_test_command("Resume % --key=123");
	exec_test_command("Open % --key=123 --dry-run");
}


void test_backend(__attribute__((unused)) char * device) {
	printf("start testing backend\n");
	printf("test_create_open_chain");
	// test_create_open_chain(device);
	test_basic_open_and_close(device);
}
