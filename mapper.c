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
#include <signal.h>
#include <unistd.h>

#define SECTOR_SIZE 512

#pragma once



void create_fat32_on_device(const char * device){
	
	pid_t pid = vfork();
	if (pid == -1) {
		print_error("Failed to create FAT32 on", device, "vfork failed");
	}
	
	if (pid == 0) {
		int nullfd = open("/dev/null", O_WRONLY);
		dup2(nullfd, STDOUT_FILENO);
		close(nullfd);
		
		execl("/usr/sbin/mkfs.vfat", "mkfs.vfat", device, "-I", NULL);
		execl("/sbin/mkfs.vfat", "mkfs.vfat", device, "-I", NULL);
		print_error_no_exit("Failed to create FAT32 on", device, "Make sure that mkfs has installed");
		kill(getppid(), SIGQUIT);
		exit(1);
	}
}

bool detect_fat32_on_device(const char * device){
	uint8_t content[20];
	FILE * fp = fopen(device, "rb");
	if (fp == NULL) {
		print_error("can not open device:", device);
	}
	if (fread(content, 1, sizeof(content), fp) != sizeof(content)){
		print_error("Failed to detect partition on", device);
	}
	fclose(fp);
	return memcmp(&content[3], "mkfs.fat", 8) == 0;
}

bool check_is_device_mounted(char * device){
	FILE *fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		print_warning("Cannot detect device", device, "mount status.");
		return false;
	}
	
	char *line = NULL;
	size_t len = 0;
	char * location;
	
	while ((getline(&line, &len, fp)) != -1) {
		
		if ((location = strstr(line, device)) != NULL) {
			fclose(fp);
			char * token = strtok(location + strlen(device) + 1, " ");
			print_error("Device", device, "is mounted at", token, ". Unmount to open device.");
		}
	}
	free(line);
	fclose(fp);
	return false;
}

size_t get_device_sector_cnt(const char * device) {
	int fd = open(device, O_RDONLY);
	if (fd == -1) {
		print_error("can not open device:", device);
	}
	
	size_t size;
	if (ioctl(fd, BLKGETSIZE, &size) == -1) {
		close(fd);
		print_error("can not get size from block device:", (char *)device, "reasion:", strerror(errno));
	}
	
	close(fd);
	return size;
}

void decide_start_and_end_sector(const char * device, bool is_decoy, size_t * start_sector, size_t * end_sector){
	size_t device_size = get_device_sector_cnt(device);
	size_t safe_node = (0x78000b + (16<<20)) / 512; // safe sector
	if (is_decoy){
		if (device_size < (128<<20) / 512){
			print_error("Device", device, "is too small to deploy decoy partition.");
		}
		*end_sector = device_size - 4;
		*start_sector = (device_size - safe_node) * 4 / 12 + safe_node;
	} else {
		if (device_size < (32<<20)){
			print_error("Device", device, "is too small.");
		}
		*start_sector = 4;
		*end_sector = device_size;
	}
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

int create_crypt_mapping(const char * device, const char * name, const char * enc_type, const char * password, size_t start_sector, size_t end_sector, bool read_only) {
	struct dm_task * dmt;
	char params[512];
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
	

	if (!dm_task_add_target(dmt, 0, end_sector - start_sector, "crypt", params)) {
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

void create_crypt_mapping_from_disk_key(const char * device, const char * target_name, Metadata metadata, const uint8_t disk_key[HASHLEN], bool read_only){
	char password[HASHLEN * 2 + 1];
	convert_password_from_disk_key(disk_key, password);
	create_crypt_mapping(device, target_name, metadata.enc_type, password, metadata.start_sector, metadata.end_sector, read_only);
}

void get_header_from_device(Data *data, const char *device, int64_t offset) {
	FILE *fp;
	size_t result;

	fp = fopen(device, "rb");
	if (fp == NULL) {
		print_error("Failed to open block device", device);
	}
	
	if (offset < 0) {
		fseek(fp, offset, SEEK_END);
	} else {
		fseek(fp, 0, SEEK_SET);
	}
	
	result = fread(data, 1, sizeof(Data), fp);
	if (result != sizeof(Data)) {
		print_error("Failed to read block device", device);
	}
	fclose(fp);
}


void write_header_to_device(const Data * data, const char * device, int64_t offset){
	FILE *fp;
	size_t result;
	
	fp = fopen(device, "r+b");
	if (fp == NULL) {
		print_error("Failed to open block device", device);
	}
	
	if (offset < 0) {
		fseek(fp, offset, SEEK_END);
	} else {
		fseek(fp, 0, SEEK_SET);
	}
	
	result = fwrite(data, 1, sizeof(Data), fp);
	if (result != sizeof(Data)) {
		print_error("Failed to write to block device", device);
	}
	
	fclose(fp);
}
