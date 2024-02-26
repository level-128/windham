//
// Created by level-128 on 1/19/24.
//

#include "bklibkey.c"
#include "bksrclib.c"
#include "windham_const.h"

void action_open(const char * device, const char * target_name, unsigned timeout,
                 PARAMS_FOR_KEY,
                 ARGFLG(is_dry_run, is_decoy, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue, is_no_map_partition, is_nokeyring)){
	Data data;
	size_t offset;
	Dynenc_param dynenc_param;
	uint8_t disk_key[HASHLEN];
	
	CHECK_DEVICE_TOPOLOGY("/dev", parent,
	                      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(mount_points_len, > 0, mount_points,
			                      (_("Cannot open device %s, device has been mounted at %s. Unmount the device to continue"), device, mount_points[0]),
			                      (_("Cannot open device %s, unmount the device to continue. Active mount points:"), device));
			                      
	                      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(child_ret_len, > 1, child,
	                            (_("device %s has already been mapped as \"%s\" either by Windham or other device mapper schemes."), device, child[0]),
	                            (""));
	);
	
	if (is_nokeyring) {
		is_kernel_keyring_exist = false;
	} else {
		kernel_keyring_init();
	}
	
	switch (frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy)) {

		// Case 1: Open a suspend partition
		case NMOBJ_MAPPER_DEVSTAT_SUSP: {
			if (!is_dry_run) {
				uint8_t zeros[HASHLEN] = {0};
				get_metadata_key_or_disk_key_from_master_key(data.metadata.disk_key_mask, zeros, data.uuid_and_salt, disk_key);
				create_crypt_mapping_from_disk_key(device, target_name, data.metadata.enc_type, disk_key, data.uuid_and_salt, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue, is_no_map_partition);
				print_warning(_("Device %s is unlocked and suspended. Don't forget to close it using \"Resume\" when appropriate."), device);
			} else {
				char uuid_str[37];
				generate_UUID_from_bytes(data.uuid_and_salt, uuid_str);
				printf(_("dry run complete. Device is unlocked and suspended, thus no key slot status could be provided\n"));
				printf(_("Additional device parameters: \n"
				         "UUID: %s\n"
				         "Crypto algorithm: %s\n"
				         "Start sector %lu\n"
				         "End sector %lu\n"
				         "Block size %hu\n"), uuid_str, data.metadata.enc_type, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size);
			}
			return;
		}
		// END case 1 ---------------------------------------------------------------------------------------------------------------------------

		// Case 2: Open a converting partition
		case NMOBJ_MAPPER_DEVSTAT_CONV: {
			printf(_("Device %s has been aborted from the last conversion. Continue converting... \n"), device);
			
			OPERATION_BACKEND_UNENCRYPT_HEADER
			
			dynesc_calc_param(&dynenc_param, STR_device->block_size, data.metadata.section_size);
			
			get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, data.uuid_and_salt, disk_key);

			create_crypt_mapping_from_disk_key(device, ".tmp_windham", data.metadata.enc_type, disk_key, data.uuid_and_salt, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size,  false, false, true, true, true);
			
			printf(_("Probing for the area where the encryption was interrupted..."));
			uint64_t copy_disk_start = check_disk_hash(dynenc_param, device);
			printf(_(" complete, at section %lu\n"), copy_disk_start);
			
			copy_disk(dynenc_param, device, "/dev/mapper/.tmp_windham", copy_disk_start);
			
			offset = 0; // write as normal header
			bool is_assign_new_head = true;
			OPERATION_LOCK_AND_WRITE
			
			sync();
			
			// obliterate the old header
			fill_secure_random_bits((uint8_t *) &data, sizeof(Data));
			write_header_to_device(&data, device, (int64_t) -4096);
			
			remove_crypt_mapping(".tmp_windham");
			printf(_("Dynamic convert has complete. Please use the same command to open the partition."));
			break;
		}
		// END case 2 ---------------------------------------------------------------------------------------------------------------------------

		// Case 3 & 4: Open a partition
		case NMOBJ_MAPPER_DEVSTAT_NORM: // only read key from keyring when the device is not decoy
			switch (mapper_keyring_get_serial(data.uuid_and_salt, disk_key)) {
				case NMOBJ_KEY_OK:
					printf(_("Found kernel keyring key\n"));
					
					size_t start_sector, end_sector;
					size_t device_block_cnt = STR_device->block_size;
					decide_start_and_end(device, device_block_cnt, &start_sector, &end_sector, DEFAULT_BLOCK_SIZE, false);
					create_crypt_mapping_from_disk_key(device, target_name, DEFAULT_DISK_ENC_MODE, disk_key, data.uuid_and_salt, start_sector, end_sector, DEFAULT_BLOCK_SIZE, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue, is_no_map_partition);

					return;
				case NMOBJ_KEY_ERR_KEYREVOKED:
				print_warning(_("The stored key in kernel keyring subsystem has removed. re-unlocking %s to /dev/mapper/%s..."), device, target_name);
					break;
				case NMOBJ_KEY_ERR_KEYEXPIRED:
				print_warning(_("The stored key in kernel keyring subsystem has expired. re-unlocking %s to /dev/mapper/%s..."), device, target_name);
					break;
				case NMOBJ_KEY_ERR_KEYCTL_READ:
				print_warning(_("Cannot read the key in the keyring system. The key may has been modified. re-unlocking %s to /dev/mapper/%s..."), device, target_name);
				case NMOBJ_KEY_ERR_NOKEY:
				case NMOBJ_KEY_ERR_KERNEL_KEYRING:
					break;
			}
			// falls through
		case NMOBJ_MAPPER_DEVSTAT_DECOY: { // unlock when NMOBJ_MAPPER_DEVSTAT_NORM and NMOBJ_MAPPER_DEVSTAT_DECOY
			
			printf(_("Unlocking %s to /dev/mapper/%s...\n"), device, target_name);
			OPERATION_BACKEND_UNENCRYPT_HEADER
			
			if (!is_dry_run) {
				get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, data.uuid_and_salt, disk_key);
				if (timeout) {
					if (is_decoy) {
						print_warning(_("key from the Decoy partition cannot be registered in Kernel Keyring service."));
					} else {
						printf(_("Registering the key into keyring with lifetime: %u sec.\n"), timeout);
						mapper_keyring_add_key(disk_key, data.uuid_and_salt, data.metadata, timeout);
					}
				}
				
				create_crypt_mapping_from_disk_key(device, target_name, data.metadata.enc_type, disk_key, data.uuid_and_salt, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue, is_no_map_partition);

			} else {
				char uuid_str[37];
				generate_UUID_from_bytes(data.uuid_and_salt, uuid_str);
				printf(_("dry run complete. Slot %i opened with master key:\n"), unlocked_slot);
				print_hex_array(HASHLEN, master_key);
				printf(_("Additional device parameters: \n"
				         "UUID: %s\n"
				         "Crypto algorithm: %s\n"
				         "Start sector %lu\n"
				         "End sector %lu\n"
				         "Block size %hu\n"), uuid_str, data.metadata.enc_type, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size);
				printf(_("key slot status:\n"));
				
				uint8_t temp[HASHLEN] = {0};
				for (int i = 0; i < KEY_SLOT_COUNT; i++) {
					if (data.metadata.key_slot_is_used[i]) {
						if (memcmp(data.metadata.keyslot_key[i], temp, HASHLEN) == 0) {
							printf(_("Slot %i has been revoked.\n"), i);
						} else {
							printf(_("Slot %i occupied with password; identifier: "), i);
							print_hex_array(HASHLEN / 4, data.metadata.keyslot_key[i]);
						}
					} else {
						printf(_("Slot %i is empty.\n"), i);
					}
				}
			} // if (!is_dry_run) { ... } else { ...
		} // case NMOBJ_MAPPER_DEVSTAT_DECOY: {
	} // switch (frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy)) {
}
