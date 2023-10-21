//
// Created by level-128 on 8/28/23.
//
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "libdevmapper.h"

#include <libintl.h>

#define SECTOR_SIZE 512

#pragma once

typeof(dm_task_create) * p_dm_task_create;
typeof(dm_task_set_name) * p_dm_task_set_name;
typeof(dm_task_run) * p_dm_task_run;
typeof(dm_task_destroy) * p_dm_task_destroy;
typeof(dm_task_add_target) * p_dm_task_add_target;

void mapper_init(){
	void* handle = dlopen("libdevmapper.so", RTLD_LAZY);
	if (!handle) {
		print_error(_("error loading libdevmapper.so. Please install 'libdevmapper' (under debian-based distro) or 'device-mapper' (under fedora/opensuse-based distro)"));
	}
	
	p_dm_task_create = dlsym(handle, "dm_task_create");
	p_dm_task_set_name = dlsym(handle, "dm_task_set_name");
	p_dm_task_run = dlsym(handle, "dm_task_run");
	p_dm_task_destroy = dlsym(handle, "dm_task_destroy");
	p_dm_task_add_target = dlsym(handle, "dm_task_add_target");
};


void create_fat32_on_device(const char * device){
	
	pid_t pid = vfork();
	if (pid == -1) {
		print_error(_("Failed to create FAT32 on %s vfork failed"), device);
	}
	
	if (pid == 0) {
		int nullfd = open("/dev/null", O_WRONLY);
		dup2(nullfd, STDOUT_FILENO);
		close(nullfd);
		
		execl("/usr/sbin/mkfs.vfat", "mkfs.vfat", device, "-I", NULL);
		execl("/sbin/mkfs.vfat", "mkfs.vfat", device, "-I", NULL);
		print_error_no_exit(_("Failed to create FAT32 on %s, Make sure that mkfs has installed"), device);
		kill(getppid(), SIGQUIT);
		exit(1);
	}
}

bool detect_fat32_on_device(const char * device){
	uint8_t content[20];
	FILE * fp = fopen(device, "rb");
	if (fp == NULL) {
		print_error(_("can not open device %s"), device);
	}
	if (fread(content, 1, sizeof(content), fp) != sizeof(content)){
		print_error(_("Failed to detect partition on %s"), device);
	}
	fclose(fp);
	return memcmp(&content[3], "mkfs.fat", 8) == 0;
}

bool check_is_device_mounted(char * device){
	FILE *fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		print_warning(_("Cannot detect device %s mount status."), device);
		return false;
	}
	
	char *line = NULL;
	size_t len = 0;
	char * location;
	
	while ((getline(&line, &len, fp)) != -1) {
		
		if ((location = strstr(line, device)) != NULL) {
			fclose(fp);
			char * token = strtok(location + strlen(device) + 1, " ");
			print_error(_("Device %s is mounted at %s. Unmount to open device."), device, token);
		}
	}
	free(line);
	fclose(fp);
	return false;
}

size_t get_device_sector_cnt(const char * device) {
	int fd = open(device, O_RDONLY);
	if (fd == -1) {
		print_error(_("can not open device %s"), device);
	}
	
	size_t size;
	if (ioctl(fd, BLKGETSIZE, &size) == -1) {
		close(fd);
		print_error(_("can not get size from block device %s, reason: %s"), device, strerror(errno));
	}
	
	close(fd);
	return size;
}

void decide_start_and_end_sector(const char * device, bool is_decoy, size_t * start_sector, size_t * end_sector){
	size_t device_size = get_device_sector_cnt(device);
	size_t safe_node = (0x78000b + (16<<20)) / 512; // safe sector
	if (is_decoy){
		if (device_size < (128<<20) / 512){
			print_error(_("Device %s is too small to deploy decoy partition; Windham requires at least %i MiB."), device, 128);
		}
		*end_sector = device_size - 4;
		*start_sector = (device_size - safe_node) * 4 / 12 + safe_node;
	} else {
		if (device_size < (32<<20) / 512){
			print_error(_("Device %s is too small; Windham requires at least %i MiB."), device, 32);
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
	if (!(dmt = p_dm_task_create(DM_DEVICE_REMOVE))) {
		print_error(_("dm_task_create failed when remove mapping for device %s"), name);
	}
	if (!p_dm_task_set_name(dmt, name)) {
		p_dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	if (!p_dm_task_run(dmt)) {
		print_error(_("dm_task_run failed when remove mapping for device %s"), name);
		p_dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
}

int create_crypt_mapping(const char * device, const char * name, const char * enc_type, const char * password, size_t start_sector, size_t end_sector, __attribute__((unused)) bool read_only) {
	struct dm_task * dmt;
	char params[512];
//	print("device size", device_size, " start sector", start_sector);
	
	snprintf(params, sizeof(params), "%s %s 0 %s %zu", enc_type, password, device, start_sector);
//	print("crypt_map argument:", params);
	
	if (!(dmt = p_dm_task_create(DM_DEVICE_CREATE))) {
		print_error(_("dm_task_create failed when mapping device %s"), name);
	}
	
	if (!p_dm_task_set_name(dmt, name)) {
		p_dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	

	if (!p_dm_task_add_target(dmt, 0, end_sector - start_sector, "crypt", params)) {
		print_error(_("dm_task_add_target failed when mapping device %s"), name);
		p_dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	
	if (!p_dm_task_run(dmt)) {
		print_error(_("p_dm_task_run failed when mapping device %s"), name);
		p_dm_task_destroy(dmt);
		exit(EXIT_FAILURE);
	}
	
	p_dm_task_destroy(dmt);
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
		print_error(_("Failed to open %s"), device);
	}
	
	if (offset < 0) {
		fseek(fp, offset, SEEK_END);
	} else {
		fseek(fp, 0, SEEK_SET);
	}
	
	result = fread(data, 1, sizeof(Data), fp);
	if (result != sizeof(Data)) {
		print_error(_("Failed to read %s"), device);
	}
	fclose(fp);
}


void write_header_to_device(const Data * data, const char * device, int64_t offset){
	FILE *fp;
	size_t result;
	
	fp = fopen(device, "wb"); // ensure that if 'device' is not a block device, empty the file.
	if (fp == NULL) {
		print_error(_("Failed to open %s"), device);
	}
	
	if (offset < 0) {
		fseek(fp, offset, SEEK_END);
	} else {
		fseek(fp, offset, SEEK_SET);
	}
	
	result = fwrite(data, 1, sizeof(Data), fp);
	if (result != sizeof(Data)) {
		print_error(_("Failed to write %s"), device);
	}
	
	fclose(fp);
}