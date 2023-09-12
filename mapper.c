//
// Created by level-128 on 8/28/23.
//
#include <libdevmapper.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <assert.h>
#include <errno.h>

#define SECTOR_SIZE 512

#pragma once

size_t get_device_sector_cnt(const char * device) {
	int fd = open(device, O_RDONLY);
	if (fd == -1) {
		print_error("can not open device:", device);
	}
	
	unsigned long size;
	if (ioctl(fd, BLKGETSIZE, &size) == -1) {
		close(fd);
		print_error("can not get size from block device:", (char *)device, "reasion:", strerror(errno));
	}
	
	close(fd);
	return size;
}



void convert_password_from_disk_key(const uint8_t master_key[32], char key[HASHLEN * 2 + 1]) {
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
		exit(EXIT_FAILURE);
	}
	if (!dm_task_run(dmt)) {
		print_error_no_exit("dm_task_run failed");
		dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
}

int create_crypt_mapping(const char * device, const char * name, const char * enc_type, const char * password, size_t start_byte, bool read_only) {
	struct dm_task * dmt;
	char params[512];
	size_t device_size = get_device_sector_cnt(device);
	size_t start_sector = ((start_byte + SECTOR_SIZE - 1) / SECTOR_SIZE);
	start_sector = (start_sector + 3) / 4 * 4;
	
//	print("device size", device_size, " start sector", start_sector);
	
	snprintf(params, sizeof(params), "%s %s 0 %s %zu", enc_type, password, device, start_sector);
//	print("crypt_map argument:", params);
	
	if (!(dmt = dm_task_create(DM_DEVICE_CREATE))) {
		print_error("dm_task_create failed");
	}
	
	if (!dm_task_set_name(dmt, name)) {
		print_error_no_exit("dm_task_set_name failed");
		dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	

	if (!dm_task_add_target(dmt, 0, device_size - start_sector, "crypt", params)) {
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

void create_crypt_mapping_from_disk_key(const char * device, const char * target_name, const char * enc_type, const uint8_t disk_key[HASHLEN], size_t start_byte, bool read_only){
	char password[HASHLEN * 2 + 1];
	convert_password_from_disk_key(disk_key, password);
	create_crypt_mapping(device, target_name, enc_type, password, start_byte, read_only);
}

void get_header_from_device(Data * data, const char * device){
	FILE * fd = fopen(device, "r");
	if (fd == NULL) {
		print_error("Failed to open block device", device);
	}
	size_t read_size = fread(data, 1, sizeof(Data), fd);
	if (read_size != sizeof(Data)) {
		print_error("IO error while reading block device", device);
	}
	assert(fclose(fd) == 0);
}

void write_header_to_device(const Data * data, const char * device){
	FILE * fd = fopen(device, "w");
	if (fd == NULL) {
		print_error("Failed to open block device", device);
	}
	size_t read_size = fwrite(data, 1, sizeof(Data), fd);
	if (read_size != sizeof(Data)) {
		print_error("IO error while writing block device", device);
	}
	assert(fclose(fd) == 0);
}
