//
// Created by level-128 on 8/28/23.
//
#include <libdevmapper.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/fs.h>

unsigned long get_device_size(const char * device) {
	int fd = open(device, O_RDONLY);
	if (fd == -1) {
		print_error("can not open device:", device);
	}
	
	unsigned long size;
	if (ioctl(fd, BLKGETSIZE, &size) == -1) {
		close(fd);
		print_error("can not get size from block device:", device);
	}
	
	close(fd);
	return size;
}

void create_password(const uint8_t master_key[HASHLEN], char key[HASHLEN * 2]) {
	const char *hex_chars = "0123456789abcdef";
	
	for (size_t i = 0; i < HASHLEN; ++i) {
		uint8_t byte = master_key[i];
		key[i * 2]     = hex_chars[(byte >> 4) & 0xF];
		key[i * 2 + 1] = hex_chars[byte & 0xF];
	}
	
	key[HASHLEN * 2] = '\0';  // Null-terminate the string
}

void remove_crypt_mapping(const char * name) {
	struct dm_task * dmt;
	if (!(dmt = dm_task_create(DM_DEVICE_REMOVE))) {
		print_error("dm_task_create failed");
	}
	if (!dm_task_set_name(dmt, name)) {
		print_error_no_exit("dm_task_set_name failed");
		dm_task_destroy(dmt);
	}
	if (!dm_task_run(dmt)) {
		print_error_no_exit("dm_task_run failed");
		dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
}

int create_crypt_mapping(const char * device, const char * name, const char * enc_type, const char * password) {
	struct dm_task * dmt;
	char params[512];
	uint64_t device_size = get_device_size(device);
	
	
	if (device_size == 0) {
		fprintf(stderr, "Failed to get device size\n");
		return 1;
	}
	
	snprintf(params, sizeof(params), "%s %s 0 %s 0", enc_type, password, device);
	
	if (!(dmt = dm_task_create(DM_DEVICE_CREATE))) {
		print_error("dm_task_create failed");
	}
	
	if (!dm_task_set_name(dmt, name)) {
		print_error_no_exit("dm_task_set_name failed");
		dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	
	if (!dm_task_add_target(dmt, 0, device_size, "crypt", params)) {
		print_error_no_exit("dm_task_add_target failed");
		dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	
	if (!dm_task_run(dmt)) {
		print_error_no_exit("dm_task_run failed");
		dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	
	dm_task_destroy(dmt);
	return 0;
}