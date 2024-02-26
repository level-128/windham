//
// Created by level-128 on 1/20/24.
//

#include "bklibkey.c"
#include "bksrclib.c"
#include "../library_intrnlsrc/mapper.c"
#include "../library_intrnlsrc/srclib.c"
#include <stdio.h>
#include <string.h>


void action_close(const char * device) {
	bool is_free_loop = false;
	CHECK_DEVICE_TOPOLOGY("/dev/mapper", child,
								       CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(mount_points_len, > 0, mount_points,
			                      (_("Cannot close device %s, device has been mounted at %s. Unmount the device to continue"), device, mount_points[0]),
			                      (_("Cannot close device %s, unmount the device to continue. Active mount points:"), device));
			                      
			                      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(parent_ret_len, > 1, parent,
			                      (_("The associate device %s has multiple parents. This is likely because the partition mapping scheme has been modified since last setup. Windham can not close this device."), device),
			                      ("")) else {
											 is_free_loop = true;
										 }
	);
	remove_crypt_mapping(device);
	if (is_free_loop){
		free_loop(parent[0]);
	}
}


int action_addkey(const char * device, PARAMS_FOR_KEY, int target_slot, uint64_t target_memory, double target_time, bool is_decoy, bool is_no_detect_entropy) {
	Data data;
	size_t offset;
	ENUM_MAPPER_DEVSTAT device_stat = frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy);
	if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
		print_error(_("The header is suspended. Resume header to perform this operation."));
	}
	
	OPERATION_BACKEND_UNENCRYPT_HEADER
	
	Key new_key;
	interactive_prepare_key(&new_key, device);
	int added_slot = add_key_to_keyslot(&data, master_key, new_key, device, target_slot, target_memory, target_time, is_no_detect_entropy);
	
	bool is_assign_new_head = true;
	OPERATION_LOCK_AND_WRITE
	return added_slot;
}

int action_revokekey(const char * device, PARAMS_FOR_KEY, bool is_revoke_all, bool is_obliterate, bool is_decoy) {
	Data data;
	size_t offset;
	ENUM_MAPPER_DEVSTAT device_stat = frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy);
	
	if (is_revoke_all) {
		for (int i = 0; i < KEY_SLOT_COUNT; i++) {
			revoke_given_key_slot(&data, i, false);
		}
		write_header_to_device(&data, device, (int64_t) offset);
		return -1;
	} else if (is_obliterate) {
		ask_for_conformation(_("Device %s will not be accessible, even if holding the master key, unless backup has created. Continue?"), device);
		for (int i = 0; i < 3; i++) {
			fill_secure_random_bits((uint8_t *) &data, sizeof(Data));
			write_header_to_device(&data, device, (int64_t) offset);
		}
		return -1;
	} else if (target_unlock_slot != -1) {
		revoke_given_key_slot(&data, target_unlock_slot, false);
		write_header_to_device(&data, device, (int64_t) offset);
		return target_unlock_slot;
	}
	
	if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
		print_error(_("The header is suspended. Resume header to perform this operation."));
	}
	
	OPERATION_BACKEND_UNENCRYPT_HEADER
	
	revoke_given_key_slot(&data, unlocked_slot, true);
	
	bool is_assign_new_head = true;
	OPERATION_LOCK_AND_WRITE
	return unlocked_slot;
}

void action_backup(const char * device, const char * filename, PARAMS_FOR_KEY, bool is_no_transform, bool is_decoy) {
	if (access(filename, F_OK) != -1) {
		print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename) {}
	}
	
	Data data;
	size_t offset;
	ENUM_MAPPER_DEVSTAT device_stat = frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy);
	if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
		print_error(_("The header is suspended. Resume header to perform this operation."));
	}
	
	if (is_no_transform) {
		write_header_to_device(&data, filename, 0);
	} else {
		OPERATION_BACKEND_UNENCRYPT_HEADER
		device = filename;
		offset = 0;
		bool is_assign_new_head = true;
		OPERATION_LOCK_AND_WRITE
	}
}

void action_restore(const char * device, const char * filename, bool is_decoy) {
	if (is_decoy) {
		ask_for_conformation(_("Restoring header to device \"%s\" as decoy partition, All content will be lost. Continue?"), device);
	} else {
		ask_for_conformation(_("Restoring header to device \"%s\", All content will be lost. Continue?"), device);
	}
	
	Data data;
	size_t offset;
	frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(filename, &data, &offset, &is_decoy);
	
	write_header_to_device(&data, device, is_decoy ? -4096 : 0);
}

void action_suspend(const char * device, PARAMS_FOR_KEY, bool is_decoy) {
	Data data;
	size_t offset;
	frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy);
	
	if (is_header_suspended(data)) {
		print_error(_("The device %s is already suspended."), device);
	}
	Data data_copy;
	memcpy(&data_copy, &data, sizeof(data_copy));
	OPERATION_BACKEND_UNENCRYPT_HEADER // get master key and validate
	do {
		suspend_encryption(&data_copy, master_key);
		write_header_to_device(&data_copy, device, offset);
	} while (0);
}

void action_resume(const char * device, PARAMS_FOR_KEY, bool is_decoy) {
	Data data;
	size_t offset;
	frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy);
	
	if (!is_header_suspended(data)) {
		print_error(_("The device %s is already encrypted."), device);
	}
	Data data_copy;
	memcpy(&data_copy, &data, sizeof(data_copy));
	// unlock the header but not validate key using metadata. metadata is a mess right now.
	get_master_key(data, master_key, key, device, target_unlock_slot, max_unlock_mem, max_unlock_time);
	
	resume_encryption(&data_copy, master_key);
	write_header_to_device(&data_copy, device, (int64_t) offset);
}