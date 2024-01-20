//
// Created by level-128 on 8/28/23.
//
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux_fs.h>

#include <libdevmapper.h>

#include "srclib.c"

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
	
	print("create_crypt_mapping:: size:", end_sector - start_sector, "params:", params_crypt);
	
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
						  " are properly set. To stop using kernel keyrings, use \"--nokeyring\""), name);
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
                                        bool read_only,
                                        bool is_allow_discards,
                                        bool is_no_read_workqueue,
                                        bool is_no_write_workqueue,
                                        bool is_no_map_partition) {
	 
	char password[HASHLEN * 2 + 1];
	convert_disk_key_to_hex_format(disk_key, password);
	
	char uuid_str[37];
	generate_UUID_from_bytes(uuid, uuid_str);
	
	create_crypt_mapping(device, target_name, metadata->enc_type, password, uuid_str, metadata->start_sector, metadata->end_sector, metadata->block_size, read_only,
	                     is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);
	
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
	check_container();
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
	
	if (access("/dev/mapper/.tmp_windham", F_OK) == 0) {
		print_warning(_("It was detected that the program did not end properly at the last conversion."));
		remove_crypt_mapping("/dev/mapper/.tmp_windham");
	}
}

#endif