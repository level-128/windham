//
// Created by level-128 on 8/31/23.
//

#include "testutil.c"


void test_basic_open_and_close(char * device_) {
	create_new_device(device_);
	exec_test_command("New % --key=123 --target-time=0.1");
	find_four_target(device_); // check is target all random

	exec_test_command("Open % --key=123 --max-unlock-time=1 --dry-run");
	exec_test_command("Close enc1");
	interactive_ask_new_key_test_key = "sdasda";
	exec_test_command("AddKey % --key=123 --target-time=0.1 --rapid-add");
	interactive_ask_new_key_test_key = "1234";
	exec_test_command("AddKey % --key=123 --target-time=0.1");
	interactive_ask_new_key_test_key = "12345";
	exec_test_command("AddKey % --key=123 --target-time=0.1");
	interactive_ask_new_key_test_key = "12346";
	exec_test_command("AddKey % --key=123 --target-time=0.1");
	interactive_ask_new_key_test_key = "12347";
	exec_test_command("AddKey % --key=123 --target-time=0.1");
	interactive_ask_new_key_test_key = "1234";
	exec_test_error_command("AddKey % --key=123 --target-time=0.1");
	exec_test_command("Open % --key=1234 --max-unlock-time=1 --dry-run");
	exec_test_command("DelKey % --key=12347 --max-unlock-time=1");
	exec_test_error_command("Open % --key=12347 --max-unlock-time=1 --dry-run");
}


void test_suspend_chain(char * device_) {
	create_new_device(device_);
	exec_test_command("New % --key=123 --target-time=0.1");
	exec_test_command("Suspend % --key=123");
	exec_test_error_command("Suspend % --key=123");
	exec_test_error_command("AddKey % --key=123");
	exec_test_command("Open % --key=123 --dry-run --max-unlock-time=1");
	exec_test_command("Resume % --key=123");
	exec_test_command("Open % --key=123 --dry-run --max-unlock-time=1");
}


void test_backend(__attribute__((unused)) char * device) {
	test_basic_open_and_close(device);
	test_suspend_chain(device);
}
