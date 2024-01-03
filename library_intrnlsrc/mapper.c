//
// Created by level-128 on 8/28/23.
//
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux_fs.h>

#include <libdevmapper.h>

#include "srclib.c"

#define SECTOR_SIZE 512
#define MAX_LINE_LENGTH 1024
#define TARGET_PREFIX "name         : "

// data
#ifndef INCL_MAPPER
#define INCL_MAPPER

typeof(dm_task_create) * p_dm_task_create;
typeof(dm_task_set_name) * p_dm_task_set_name;
typeof(dm_task_set_ro) * p_dm_task_set_ro;
typeof(dm_task_set_uuid) * p_dm_task_set_uuid;
typeof(dm_task_run) * p_dm_task_run;
typeof(dm_task_destroy) * p_dm_task_destroy;
typeof(dm_task_add_target) * p_dm_task_add_target;
typeof(dm_task_update_nodes) * p_dm_task_update_nodes;

#pragma GCC poison dm_task_create dm_task_set_name dm_task_set_ro dm_task_run dm_task_destroy dm_task_add_target dm_task_set_uuid

void check_container(void) {
	char * container = NULL;
	if (getenv("container")) {
		container = "Flatpak";
	} else if (getenv("APPIMAGE")) {
		container = "Appimage";
	} else if (getenv("SNAP")) {
		container = "Snap";
	}
	if (container) {
		print_warning(_("Running inside a container (%s) is discouraged. Windham needs to interact with the Linux kernel, thus the isolation policy of the container may render the "
		                "program malfunction."), container);
	}
}

void mapper_init() {
	void * handle = dlopen("libdevmapper.so", RTLD_LAZY);
	if (!handle) {
		print_error(_("error loading libdevmapper.so, on-the-fly encryption cannot be supported. Please install 'libdevmapper' (under debian-based distro) or 'device-mapper' (under "
		              "fedora/opensuse-based distro)"));
	} else {
		p_dm_task_create = dlsym(handle, "dm_task_create");
		p_dm_task_set_name = dlsym(handle, "dm_task_set_name");
		p_dm_task_set_ro = dlsym(handle, "dm_task_set_ro");
		p_dm_task_set_uuid = dlsym(handle, "dm_task_set_uuid");
		p_dm_task_run = dlsym(handle, "dm_task_run");
		p_dm_task_destroy = dlsym(handle, "dm_task_destroy");
		p_dm_task_add_target = dlsym(handle, "dm_task_add_target");
		p_dm_task_update_nodes = dlsym(handle, "dm_task_update_nodes");
	}
}

void create_fat32_on_device(const char * device) {
	int exec_ret_val;
	char * exec_dir[] = {"/sbin", "/usr/sbin", NULL};
	if (exec_name("mkfs.vfat", exec_dir, NULL, NULL, &exec_ret_val, true, device, "-I", NULL) == false){
		if (errno == ENOENT){
			print_error_no_exit(_("Failed to create FAT32 on %s, Make sure that mkfs has installed"), device);
		} else {
			print_error_no_exit(_("Failed to create FAT32 on %s."), device);
		}
	} else if (exec_ret_val != 0){
		print_error_no_exit(_("Failed to create FAT32 on %s."), device);
	};
}

typedef enum{
	NMOBJ_MAPPER_DEVSTAT_DECOY,
	NMOBJ_MAPPER_DEVSTAT_SUSP,
	NMOBJ_MAPPER_DEVSTAT_CONV,
	NMOBJ_MAPPER_DEVSTAT_NORM
} ENUM_MAPPER_DEVSTAT;

ENUM_MAPPER_DEVSTAT detect_device_status(const char * device){
	uint8_t content_head[16], content_end_head[16];
	int fp = open(device, O_RDONLY);
	if (fp == 0) {
		print_error(_("can not open device %s"), device);
	}
	read(fp, content_head, sizeof(content_head));
	
	lseek(fp, -4096, SEEK_END);
	read(fp, content_end_head, sizeof(content_end_head));
	
	close(fp);
	if (memcmp(content_end_head, head_converting, sizeof(head_converting)) == 0){
		return NMOBJ_MAPPER_DEVSTAT_CONV;
	} else if (memcmp(&content_head[3], "mkfs.fat", 8) == 0){
		return NMOBJ_MAPPER_DEVSTAT_DECOY;
	} else if (memcmp(content_head, head, sizeof(head)) == 0){
		return NMOBJ_MAPPER_DEVSTAT_SUSP;
	} else {
		return NMOBJ_MAPPER_DEVSTAT_NORM;
	}
}

bool check_is_device_mounted(const char * device) {
	FILE * fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		print_warning(_("Cannot detect device %s mount status."), device);
		return false;
	}
	
	char * line = NULL;
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

size_t get_device_block_cnt(const char * device) {
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

size_t decide_start_and_end_block(const char * device, size_t * start_sector, size_t * end_sector, size_t block_size, size_t section_size, bool is_decoy, bool is_dyn_enc) {
	size_t device_sector_cnt = get_device_block_cnt(device);
	
	size_t safe_node = (0x78000b + (16 << 20)) / 512; // safe sector
	if (is_decoy) {
		if (device_sector_cnt % (block_size / 512) != 0) {
			print_error(_("Impossible to create a decoy scheme since the size of the crypt device is not the integer multiple of the sector size."));
		}
		if (device_sector_cnt < (128 << 20) / 512) {
			print_error(_("Device %s is too small to deploy decoy partition; Windham requires at least %i MiB."), device, 128);
		}
		*end_sector = device_sector_cnt - 8;
		*start_sector = (device_sector_cnt - safe_node) * 4 / 12 + safe_node;
	} else if (is_dyn_enc){
		if (device_sector_cnt % (block_size / 512) != 0) {
			print_error(_("Impossible to convert the given device since the size of the crypt device is not the integer multiple of the sector size."));
		}
		const size_t min_size_bytes = (8 << 10) /* min size for device */ + section_size * 2 /* sector before and after the unenc data region */ + 4096 /* hash */ + 4096 /* header at the end */;
		if (device_sector_cnt < (min_size_bytes) / 512) {
			print_error(_("Device %s is too small; Windham requires at least %lu KiB to dynamically convert the partition under sector size %lu."), device, min_size_bytes, section_size);
		}
		*end_sector = device_sector_cnt;
		*start_sector = section_size / 512;
	} else {
		if (device_sector_cnt % (block_size / 512) != 0) {
			ask_for_conformation(_("The size of the crypt device is not the integer multiple of the sector size. You may experience degraded performance."));
		}
		if (device_sector_cnt < (8 << 10) / 512) {
			print_error(_("Device %s is too small; Windham requires at least %i KiB."), device, 8);
		}
		*start_sector = 8;
		*end_sector = device_sector_cnt - device_sector_cnt % (block_size / 512);
	}
	return device_sector_cnt;
}


void convert_disk_key_to_hex_format(const uint8_t master_key[32], char key[HASHLEN * 2 + 1]) {
	const char * hex_chars = "0123456789abcdef";
	
	for (size_t i = 0; i < HASHLEN; ++i) {
		uint8_t byte = master_key[i];
		key[i * 2] = hex_chars[(byte >> 4) & 0xF];
		key[i * 2 + 1] = hex_chars[byte & 0xF];
	}
	
	key[HASHLEN * 2] = '\0';  // Null-terminate the string
}


void remove_crypt_mapping(const char * name) {
	char target_loc[strlen(name) + strlen("/dev/mapper/") + 1];
	sprintf(target_loc, "/dev/mapper/%s", name);
	
	char * execdir[] = {"/sbin", "/usr/sbin", NULL};
	char * dup_stdout = NULL;
	size_t dup_stdout_len = 0;
	int exec_ret_val;
	exec_name("kpartx", execdir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, "-d", target_loc, "-v", NULL);
	
	
	struct dm_task * dmt;
	dmt = p_dm_task_create(DM_DEVICE_REMOVE);
	p_dm_task_set_name(dmt, name);
	if (!p_dm_task_run(dmt)) {
		print_error(_("dm_task_run failed when remove mapping for device %s"), name);
	}
	p_dm_task_destroy(dmt);
	free(dup_stdout);
}

__attribute__((unused)) void fill_zeros_to_integrity_superblok(const char * name) {
	FILE * file;
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
	char params_crypt[540];
	char format_crypt[70] = "%s %s 0 %s %zu %i sector_size:%zu %s %s %s";
	if (is_allow_discards) {
		param_cnt_crypt++;
	}
	if (is_no_read_workqueue) {
		param_cnt_crypt++;
	}
	if (is_no_write_workqueue) {
		param_cnt_crypt++;
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
	if (!p_dm_task_set_uuid(dmt, uuid_str)) {
		exit(EXIT_FAILURE);
	}
	if (!p_dm_task_add_target(dmt, 0, end_sector - start_sector, "crypt", params_crypt)) {
		print_error(_("dm_task_add_target crypt failed when mapping device %s"), name);
	}
	if (is_read_only) {
		assert(p_dm_task_set_ro(dmt));
	}
	if (!p_dm_task_run(dmt)) { ;
		print_error(_("p_dm_task_run failed when mapping crypt device %s. If this error occurs when trying to use kernel key for unlocking the crypt device, make sure your SELinux or AppArmour policies"
						  "are properly set. To stop using kernel keyrings, use \"--nokeyring\""), name);
	}
	p_dm_task_destroy(dmt);
	
	p_dm_task_update_nodes();
	
	return 0;
}

void create_crypt_mapping_from_disk_key(const char * device,
                                        const char * target_name,
                                        EncMetadata * metadata,
                                        const uint8_t disk_key[HASHLEN],
                                        uint8_t uuid[16],
                                        bool is_use_keyring,
                                        bool read_only,
                                        bool is_allow_discards,
                                        bool is_no_read_workqueue,
                                        bool is_no_write_workqueue,
                                        bool is_no_map_partition) {
	
	if (is_use_keyring){
		assert(disk_key == NULL);
		char password[strlen(":32:logon:windham:") + 36 /* uuid len */ + 1];
		strcpy(password, ":32:logon:windham:");
		generate_UUID_from_bytes(uuid, password + strlen(":32:logon:windham:"));
		
		size_t start_sector, end_sector;
		decide_start_and_end_block(device, &start_sector, &end_sector, DEFAULT_BLOCK_SIZE, 0, false, false);
		create_crypt_mapping(device, target_name, DEFAULT_DISK_ENC_MODE, password, password + strlen(":32:logon:windham:"), start_sector, end_sector, DEFAULT_BLOCK_SIZE, read_only,
		                     is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);
		
	} else {
		char password[HASHLEN * 2 + 1];
		convert_disk_key_to_hex_format(disk_key, password);
		
		char uuid_str[37];
		generate_UUID_from_bytes(uuid, uuid_str);
		
		create_crypt_mapping(device, target_name, metadata->enc_type, password, uuid_str, metadata->start_sector, metadata->end_sector, metadata->block_size, read_only,
		                     is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);
	}
	if (!is_no_map_partition) {
		char target_loc[strlen(target_name) + strlen("/dev/mapper/") + 1];
		sprintf(target_loc, "/dev/mapper/%s", target_name);
		
		char * execdir[] = {"/sbin", "/usr/sbin", NULL};
		int exec_ret_val;
		if (exec_name("kpartx", execdir, NULL, 0, &exec_ret_val, false, "-a", target_loc, "-p", "-partition", NULL) == false) {
			if (errno == ENOENT) {
				print_warning(_("Cannot detect and map partition table under %s."), target_loc);
			}
		}
	}
}

#endif