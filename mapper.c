//
// Created by level-128 on 8/28/23.
//
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux_fs.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include "libdevmapper.h"


#define SECTOR_SIZE 512
#define MAX_LINE_LENGTH 1024
#define TARGET_PREFIX "name         : "

typeof(dm_task_create) * p_dm_task_create;
typeof(dm_task_set_name) * p_dm_task_set_name;
typeof(dm_task_set_ro) * p_dm_task_set_ro;
typeof(dm_task_set_uuid) * p_dm_task_set_uuid;
typeof(dm_task_run) * p_dm_task_run;
typeof(dm_task_destroy) * p_dm_task_destroy;
typeof(dm_task_add_target) * p_dm_task_add_target;

#pragma GCC poison dm_task_create dm_task_set_name dm_task_set_ro dm_task_run dm_task_destroy dm_task_add_target dm_task_set_uuid

#pragma once

void check_container(void) {
	char * container = NULL;
	if (getenv("container")) {
		container = "Flatpak";
	} else if (getenv("APPIMAGE")) {
		container = "Appimage";
	} else if (getenv("SNAP")) {
		container = "Snap";
	}
	if (container){
		print_warning(_("Running inside a container (%s) is discouraged. Windham needs to interact with the Linux kernel, thus the isolation policy of the container may render the "
							 "program malfunction."), container);
	}
}

void mapper_init(){
	void* handle = dlopen("libdevmapper.so", RTLD_LAZY);
	if (!handle) {
		print_error(_("error loading libdevmapper.so. Please install 'libdevmapper' (under debian-based distro) or 'device-mapper' (under fedora/opensuse-based distro)"));
	} else {
		check_container();
		
		p_dm_task_create = dlsym(handle, "dm_task_create");
		p_dm_task_set_name = dlsym(handle, "dm_task_set_name");
		p_dm_task_set_ro = dlsym(handle, "dm_task_set_ro");
		p_dm_task_set_uuid = dlsym(handle, "dm_task_set_uuid");
		p_dm_task_run = dlsym(handle, "dm_task_run");
		p_dm_task_destroy = dlsym(handle, "dm_task_destroy");
		p_dm_task_add_target = dlsym(handle, "dm_task_add_target");
	}

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

bool check_is_device_mounted(const char * device){
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
			print_error(_("Device %s is mounted at %s. Unmount to continue."), device, token);
		}
	}
	free(line);
	fclose(fp);
	return false;
}

size_t get_device_sector_cnt(const char * device) {
	int fd = open(device, O_RDONLY);
	if (fd == -1) {
		perror("open");
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

char ** get_crypto_list() {
	int crypto_count = 0;
	FILE * file;
	char line[MAX_LINE_LENGTH];
	char ** crypto_list = NULL;
	
	file = fopen("/proc/crypto", "r");
	if (file == NULL) {
		print_warning(_("Cannot determine available encryption mode on the system. Please ensure that the kernel encryption subsystem is available."));
		return NULL;
	}
	
	while (fgets(line, sizeof(line), file)) {
		if (strncmp(line, TARGET_PREFIX, strlen(TARGET_PREFIX)) == 0) {
			char * name = line + strlen(TARGET_PREFIX);
			if (*name != '_' && strcmp("stdrng\n", name) != 0) {
				(crypto_count)++;
				crypto_list = realloc(crypto_list, sizeof(char *) * crypto_count);
				
				crypto_list[crypto_count - 1] = strdup(name);
				
				char * end = crypto_list[crypto_count - 1] + strlen(crypto_list[crypto_count - 1]) - 1;
				if (*end == '\n') {
					*end = '\0';
				}
			}
		}
	}
	crypto_list = realloc(crypto_list, sizeof(char *) * (crypto_count + 1));
	crypto_list[crypto_count] = NULL;
	fclose(file);
	return crypto_list;
}

void decide_start_and_end_sector(const char * device, bool is_decoy, size_t * start_sector, size_t * end_sector, size_t block_size){
	size_t device_size = get_device_sector_cnt(device);
	if (device_size % (block_size / 512) != 0){
		print_warning(_("The size of the device is not an integer multiple of the sector size. You may experience performance degradation."));
	}
	
	size_t safe_node = (0x78000b + (16<<20)) / 512; // safe sector
	if (is_decoy){
		if (device_size < (128<<20) / 512){
			print_error(_("Device %s is too small to deploy decoy partition; Windham requires at least %i MiB."), device, 128);
		}
		*end_sector = device_size - 8;
		*start_sector = (device_size - safe_node) * 4 / 12 + safe_node;
	} else {
		if (device_size < (32<<20) / 512){
			print_error(_("Device %s is too small; Windham requires at least %i MiB."), device, 32);
		}
		*start_sector = 8;
		*end_sector = device_size - device_size % (block_size / 512);
	}
}

void generate_UUID_from_bytes(const unsigned char bytes[16], char uuid_str[37]) {
	sprintf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	        bytes[0], bytes[1], bytes[2], bytes[3],
	        bytes[4], bytes[5], bytes[6], bytes[7],
	        bytes[8], bytes[9], bytes[10], bytes[11],
	        bytes[12], bytes[13], bytes[14], bytes[15]);
}

void convert_disk_key_to_hex_format(const uint8_t master_key[32], char key[HASHLEN * 2 + 1]) {
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
	dmt = p_dm_task_create(DM_DEVICE_REMOVE);
	p_dm_task_set_name(dmt, name);
	if (!p_dm_task_run(dmt)) {
		print_error(_("dm_task_run failed when remove mapping for device %s"), name);}
	p_dm_task_destroy(dmt);
}

void fill_zeros_to_integrity_superblok(const char * name) {
	FILE *file;
	uint8_t buffer[512] = {0};
	file = fopen(name, "w");
	if (file == NULL) {
		perror("Error opening file");
		exit(1);
	}
	
	size_t written = fwrite(buffer, 1, sizeof(buffer), file);
	if (written != sizeof(buffer)) {
		perror("Error writing to file");
		fclose(file);
		exit(1);
	}
	
	fclose(file);
}


int create_crypt_mapping(const char * device,
								 const char * name,
								 const char * enc_type,
								 const char * password,
								 char uuid_str[37],
								 size_t start_sector,
								 size_t end_sector,
								 size_t block_size,
								 bool is_read_only,
								 bool is_allow_discards,
								 bool is_no_read_workqueue,
								 bool is_no_write_workqueue) {
	struct dm_task * dmt;
	// allow_discards
	// fix_padding must be used.
	
	// make crypt params
	int param_cnt_crypt = 1;
	char params_crypt[512];
	char format_crypt[70] = "%s %s 0 %s %zu %i sector_size:%zu %s %s %s";
	if (is_allow_discards) {
		param_cnt_crypt ++;
	}
	if (is_no_read_workqueue) {
		param_cnt_crypt ++;
	}
	if (is_no_write_workqueue) {
		param_cnt_crypt ++;
	}
	
	snprintf(params_crypt, sizeof(params_crypt), format_crypt, enc_type, password, device, start_sector, param_cnt_crypt, block_size,
	         is_allow_discards ? "allow_discards" : "",
	         is_no_read_workqueue ? "no_read_workqueue" : "",
	         is_no_write_workqueue ? "no_write_workqueue" : "");
	
	if (!(dmt = p_dm_task_create(DM_DEVICE_CREATE))) {
		print_error(_("dm_task_create failed when mapping device %s"), name);
	}
	if (!p_dm_task_set_name(dmt, name)) {
		exit(EXIT_FAILURE);
	}
	if (!p_dm_task_set_uuid(dmt, uuid_str)){
		exit(EXIT_FAILURE);
	}
	if (!p_dm_task_add_target(dmt, 0, end_sector - start_sector, "crypt", params_crypt)) {
		print_error(_("dm_task_add_target crypt failed when mapping device %s"), name);
	}
	if (is_read_only) {
		assert(p_dm_task_set_ro(dmt));
	}
	if (!p_dm_task_run(dmt)) {;
		print_error(_("p_dm_task_run failed when mapping crypt device %s"), name);
	}
	p_dm_task_destroy(dmt);
	
	return 0;
}

void create_crypt_mapping_from_disk_key(const char * device,
													 const char * target_name,
													 Metadata * metadata,
													 const uint8_t disk_key[HASHLEN],
													 uint8_t uuid_and_salt[16],
													 bool read_only,
													 bool is_allow_discards,
													 bool is_no_read_workqueue,
													 bool is_no_write_workqueue) {
	
	char password[HASHLEN * 2 + 1];
	convert_disk_key_to_hex_format(disk_key, password);
	
	char uuid_str[37];
	generate_UUID_from_bytes(uuid_and_salt, uuid_str);
	
	create_crypt_mapping(device, target_name, metadata->enc_type, password, uuid_str, metadata->start_sector, metadata->end_sector, metadata->block_size, read_only,
	                     is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);
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