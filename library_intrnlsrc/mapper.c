//
// Created by level-128 on 8/28/23.
//
#include <windham_const.h>
#include <libdevmapper.h>

#include <dlfcn.h>
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

bool is_device_mapper_available;

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
	if (!is_device_mapper_available){
		print_error(_("Failed to close device mapping at \"/dev/mapper/%s\" due to missing device mapper library."), name);
	}
	
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
	if (!is_device_mapper_available){
		print_error(_("Failed to create device mapping due to missing device mapper library. \nDevice: %s\nUUID: %s"), device, uuid_str);
	}
	
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

/**
 * @brief Create a crypt mapping from a disk key
 *
 * This function creates a crypt mapping from a disk key. The crypt mapping is created using the provided device, target name,
 * encryption metadata, disk key, UUID, and other options. The function first converts the disk key to a hexadecimal format,
 * generates a UUID string from the UUID bytes, and then calls the create_crypt_mapping function to create the crypt mapping.
 * If the "is_no_map_partition" option is false, the function also attempts to detect and map the partition table under the specified target location.
 *
 * @param device The device to create the crypt mapping on
 * @param target_name The target name of the crypt mapping
 * @param metadata The encryption metadata
 * @param disk_key The disk key
 * @param uuid The UUID
 * @param read_only Flag indicating if the crypt mapping should be read-only
 * @param is_allow_discards Flag indicating if discards are allowed
 * @param is_no_read_workqueue Flag indicating if read workqueue is disabled
 * @param is_no_write_workqueue Flag indicating if write workqueue is disabled
 * @param is_no_map_partition Flag indicating if partition mapping should be skipped
 */
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
				print_warning(_("Cannot detect and map partition table under %s: kpartx does not exist."), target_loc);
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
	FILE *fp;
	char local_version[256];
	
	fp = popen("uname -r", "r");
	if (fp == NULL) {
		return;
	}
	if (fgets(local_version, sizeof(local_version)-1, fp) == NULL) {
		return;
	}
	pclose(fp);
	
	int major_a = 0, minor_a = 0;
	sscanf(local_version, "%d.%d", &major_a, &minor_a);
	
	int major_b = 0, minor_b = 0;
	sscanf(TARGET_KERNEL_VERSION, "%d.%d", &major_b, &minor_b);
	
	if(major_a > major_b || (major_a == major_b && minor_a > minor_b)) {
		printf(_("The target kernel version (%s) is older than the current system kernel version (%s). consider recompile windham if needed.\n"), TARGET_KERNEL_VERSION, local_version);
	} else if(major_a < major_b || (major_a == major_b && minor_a < minor_b)) {
		print_warning(_("The target kernel version (%s) is newer than the current system kernel version (%s). This may leads to compatibility issues. It is strongly recommended to "
							 "recompile windham on your local machine."), TARGET_KERNEL_VERSION, local_version);
	}
}

void mapper_init() {
	check_container();
	void * handle = dlopen("libdevmapper.so", RTLD_LAZY);
	if (!handle) {
		print_warning(_("error loading libdevmapper.so, on-the-fly encryption cannot be supported. Please install 'libdevmapper' (under debian-based distro) or 'device-mapper' (under "
		              "fedora/opensuse-based distro)"));
		is_device_mapper_available = false;
	} else {
		p_dm_task_create = dlsym(handle, "dm_task_create");
		p_dm_task_set_name = dlsym(handle, "dm_task_set_name");
		p_dm_task_set_ro = dlsym(handle, "dm_task_set_ro");
		p_dm_task_set_uuid = dlsym(handle, "dm_task_set_uuid");
		p_dm_task_run = dlsym(handle, "dm_task_run");
		p_dm_task_destroy = dlsym(handle, "dm_task_destroy");
		p_dm_task_add_target = dlsym(handle, "dm_task_add_target");
		p_dm_task_update_nodes = dlsym(handle, "dm_task_update_nodes");
		
		is_device_mapper_available = true;
	}
	
	if (access("/dev/mapper/.tmp_windham", F_OK) == 0) {
		print_warning(_("the program did not end properly during the last conversion."));
		remove_crypt_mapping(".tmp_windham");
	}
}

#endif