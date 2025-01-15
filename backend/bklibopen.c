#pragma once

#include "../library_intrnlsrc/windhamtab.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "windham_const.h"
#include <stdint.h>

void check_size(const char *device, Data *data_, uint8_t master_key[HASHLEN], bool is_suspend) {
  size_t block_count = STR_device->block_count / (data_->metadata.block_size / 512) * (data_->metadata.block_size / 512);
  // let STR_device->block_count align with the block size.
  if (block_count != data_->metadata.end_sector) {
    const char *q_str_size_ref = _("The device's last sector (%zu) does not match with the underlying device's size (%zu). %s");
    const char * is_suspend_str = is_suspend ? _("Cannot resize the suspend partition since windham partition is designed to be tamper resistance. "
						 "Resume the partition and re-open it to resize.")
      : _("Do you want to adjust the sector range?");
    char  q_str[strlen(q_str_size_ref) + 2 * strlen(STRINGIFY(SIZE_MAX)) + strlen(is_suspend_str)];
    sprintf(q_str, q_str_size_ref, data_->metadata.end_sector, STR_device->block_count,
	    is_suspend_str);
    if (is_suspend) {
      print_error("%s", q_str);
    }

    switch (ask_option(q_str, _("Yes."),
		       block_count < data_->metadata.end_sector ?
		       _("No, and abort the operation since the last sector is out of range."):
		       _("No."),
		       NULL)) {
    case 1:
      data_->metadata.end_sector = block_count;
      Data data;
      memcpy(&data, data_, sizeof(data));

      int64_t offset = 0;
      OPERATION_LOCK_AND_WRITE;
      return;
      
    default:
      if (block_count < data_->metadata.end_sector) {
	print_error(_("User has aborted the operation."));
      }
    }
  }
}


void action_open(const char *device,
                 const char *target_name,
                 unsigned    timeout,
                 PARAMS_FOR_KEY,
                 bool is_dry_run,
                 bool is_target_readonly,
                 bool is_allow_discards,
                 bool is_no_read_workqueue,
                 bool is_no_write_workqueue,
                 bool is_no_map_partition,
                 bool is_nokeyring) {
  Data         data;
  int64_t      offset;
  // Dynenc_param dynenc_param;
  uint8_t      disk_key[HASHLEN];

  CHECK_DEVICE_TOPOLOGY(
			device, "", parent,
			CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
							  mount_points_len, > 0, mount_points,
							  (_("Cannot open device %s: device has been mounted at %s. Unmount the device to continue"),
							   device, mount_points[0]),
							  (_("Cannot open device %s: unmount the device to continue. Active mount points:"),
							   device));
			blkid_probe          pr = blkid_new_probe_from_filename(device); blkid_do_probe(pr);
			const blkid_partlist ls = blkid_probe_get_partitions(pr); int nparts = 0;
			if (ls != NULL) {
			  // partition table present
			  nparts = blkid_partlist_numof_partitions(ls);
			} blkid_free_probe(pr);
			if (nparts != 0 && !is_decoy) {
			  print_error(
				      _("Cannot open device %s: device is in use, and most importantly: it contains a partition table. This means it "
					"can't be a normal windham partition. Make sure you choose the right device! If the target contains a decoy partition, "
					"use argument \"--decoy\"."),
				      device);
			} CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
							    child_ret_len, > 0 && nparts != 0, child,
							    (_("device %s contains partition table and already been mapped as \"%s\"."
							       "Use \"sudo partx %s -d\" to close it."),
							     device, child[0], device),
							    (_("device %s contains partition table and already been mapped. Use "
							       "\"sudo partx %s -d\" to close them. mapped locations:"),
							     device, device)
							    );

			CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
							  child_ret_len, > 0 && nparts == 0, child,
							  (_("device %s has already been mapped as \"%s\" either by Windham or other device mapper "
							     "schemes. Use \"windham Close *name*\" to close it."),
							   device, child[0]),
							  (_("device %s has already been mapped by either by Windham or other device mapper schemes. Use "
							     "\"windham Close *name*\" to close them. mapped locations:"),
							   device)
							  );
			);
  CHECK_DEVICE_TOPOLOGY_FREE(child);

  if (is_nokeyring) {
    is_kernel_keyring_exist = false;
  } else {
    kernel_keyring_init();
  }

  switch (locate_possible_header_location_and_type(device, &data, &offset, is_decoy)) {
    // Case 1: Open a suspend partition
  case NMOBJ_MAPPER_DEVSTAT_SUSP: {
    convert_metadata_endianness_to_h(&data.metadata);
    check_size(device, &data, NULL, true);

    if (!is_dry_run) {
      uint8_t zeros[HASHLEN] = {0};
      get_metadata_key_or_disk_key_from_master_key(data.metadata.disk_key_mask, zeros, data.uuid_and_salt, disk_key);
      create_crypt_mapping_from_disk_key(device, target_name, data.metadata.enc_type, disk_key, data.uuid_and_salt,
					 data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size,
					 is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue,
					 is_no_map_partition);
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
	       "Block size %hu\n"),
	     uuid_str, data.metadata.enc_type, data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size);
    }
    return;
  }

    // Case 3 & 4: Open a partition
  case NMOBJ_MAPPER_DEVSTAT_NORM: // only read key from keyring when the device is not decoy
    if (mapper_keyring_get_disk_serial(data.uuid_and_salt, disk_key) == true) {
      printf(_("Found kernel keyring key\n"));
      size_t start_sector, end_sector;
      size_t device_block_cnt = STR_device->block_count;
      get_new_header_range_and_offset_based_on_size(device, device_block_cnt, &start_sector, &end_sector, DEFAULT_BLOCK_SIZE, 0);
      create_crypt_mapping_from_disk_key(device, target_name, DEFAULT_DISK_ENC_MODE, disk_key, data.uuid_and_salt, start_sector,
					 end_sector, DEFAULT_BLOCK_SIZE, is_target_readonly, is_allow_discards, is_no_read_workqueue,
					 is_no_write_workqueue, is_no_map_partition);
      return;
    }
    // falls through
  case NMOBJ_MAPPER_DEVSTAT_DECOY: { // unlock when NMOBJ_MAPPER_DEVSTAT_NORM and NMOBJ_MAPPER_DEVSTAT_DECOY
    if (is_dry_run) {
      printf(_("Unlocking %s\n"), device);
    } else {
      printf(_("Unlocking %s to /dev/mapper/%s...\n"), device, target_name);
    }


    OPERATION_BACKEND_UNENCRYPT_HEADER
      if (!is_decoy) {
	check_size(device, &data, master_key, false);
      }

    if (!is_dry_run) {
      get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, data.uuid_and_salt, disk_key);
      if (timeout) {
	if (is_decoy) {
	  print_warning(_("key to the Decoy partition cannot be registered in the Kernel Keyring service."));
	} else {
	  mapper_keyring_add_disk_key(disk_key, data.uuid_and_salt, data.metadata, timeout);
	}
      }
      create_crypt_mapping_from_disk_key(device, target_name, data.metadata.enc_type, disk_key, data.uuid_and_salt,
					 data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size,
					 is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue,
					 is_no_map_partition);
    } else {
      char uuid_str[37];
      generate_UUID_from_bytes(data.uuid_and_salt, uuid_str);
      printf(_("dry run complete, opened with master key:\n"));
      print_hex_array(HASHLEN, master_key);
      printf(_("\nAdditional device parameters: \n"
	       "UUID: %s\n"
	       "Size (MiB): %lu\n"
	       "Crypto algorithm: %s\n"
	       "Start sector %lu\n"
	       "End sector %lu\n"
	       "Block size %hu\n"),
	     uuid_str, (data.metadata.end_sector - data.metadata.start_sector) / 2 / 1024, data.metadata.enc_type,
	     data.metadata.start_sector, data.metadata.end_sector, data.metadata.block_size);
      printf(_("\nkey slot status:\n"));

      for (int i = 0; i < KEY_SLOT_COUNT; i++) {
	if (data.metadata.keyslot_level[i] == 0) {
	  printf(_("Slot %i is empty.\n"), i);
	} else {
	  if (memcmp(data.metadata.keyslot_key[i], (uint8_t [HASHLEN]){0}, HASHLEN) == 0){
	    printf(_("Slot %i used by anonymous key.\n"), i);
	  } else {
	    printf(_("Slot %i used; identifier: "), i);
	    print_hex_array(HASHLEN / 4, data.metadata.keyslot_key[i]);
	  }
	}
      }
    } // if (!is_dry_run) { ... } else { ...
  } // case NMOBJ_MAPPER_DEVSTAT_DECOY: {
  } // switch (frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(device, &data, &offset, &is_decoy)) {
}

static void _action_open_print_summary(int i, WindhamtabEntity entities){
#define HAS_FLG(x) entities.option_flags & (1 << x)
  printf("Entity %d, pass %hu:\n", i + 1, entities.pass);
  printf("\tDevice: %s\n", entities.device);
  printf("\tTo: %s\n", entities.to);
  printf("\tKey: %s\n", entities.key);
  printf("\targs:");
  if (HAS_FLG(NMOBJ_windhamtab_ro)) {
    printf(" readonly");
  }
  if (HAS_FLG(NMOBJ_windhamtab_no_read_wq)) {
    printf(" no-read-workqueue");
  }
  if (HAS_FLG(NMOBJ_windhamtab_no_write_wq)) {
    printf(" no-write-workqueue");
  }
  if (HAS_FLG(NMOBJ_windhamtab_target_allow_discards)) {
    printf(" allow-discards");
  }
  if (HAS_FLG(NMOBJ_windhamtab_nofail)) {
    printf(" nofail");
  }
  if (HAS_FLG(NMOBJ_windhamtab_systemd)) {
    printf(" systemd");
  }
  if (HAS_FLG(NMOBJ_windhamtab_is_no_map_partition)) {
    printf(" no-map-partition");
  }
  if (HAS_FLG(NMOBJ_windhamtab_max_unlock_mem)) {
    printf(" max-unlock-mem=%zu", entities.max_unlock_mem);
  }
  if (HAS_FLG(NMOBJ_windhamtab_max_unlock_time)) {
    printf(" max-unlock-time=%f", entities.max_unlock_time);
  }
  printf("\n");
#undef HAS_FLG
}

void action_open_(const char               *uninit_device,
                  const char               *windhamtab_file,
                  const char *target_name,
                  unsigned                  timeout,
                  int                       selected_windham_pass,
                  PARAMS_FOR_KEY,
                  ARGFLG(is_dry_run,
                         is_target_readonly,
                         is_allow_discards,
                         is_no_read_workqueue,
                         is_no_write_workqueue,
                         is_no_map_partition,
                         is_nokeyring,
                         is_nofail,
                         is_selected_windhamtab_pass)) {

  if (strcmp(uninit_device, "TAB") == 0) {

    int entity_count;
    if (windhamtab_file == NULL) {
      windhamtab_file = CONFIG_WINDHAMTAB_FILE;
    }
    WindhamtabEntity *entities = parse_file(windhamtab_file, &entity_count, is_selected_windhamtab_pass, selected_windham_pass);

    if (entity_count == 0) {
      printf(_("No entities in windhamtab file. Nothing to do.\n"));
      return;
    }

    uint8_t key_raw[HASHLEN];
    
    for (int i = 0; i < entity_count; i++) {
      if (is_pid1){ // print a short summery to dmesg instead
	printk("%s: Pass %hu, Device %s, To %s, Flag %u", windhamtab_file, entities[i].pass, entities[i].device,
	       entities[i].to, entities[i].option_flags);
      } else {
	_action_open_print_summary(i, entities[i]);
      }
      
#define HAS_FLGI(x) entities[i].option_flags & (1 << x)
      
      init_device(entities[i].device, false /* do not create loop for windhamtab */, false,
		  HAS_FLGI(NMOBJ_windhamtab_nofail), true);
	 
      // set key for each entity
      if (strcmp(entities[i].key, "ASK") == 0) {
	// if user uses --key, then ASK does nothing.
	if (key.key_type !=  NMOBJ_key_file_type_key){
	  key.key_type = HAS_FLGI(NMOBJ_windhamtab_systemd) ? NMOBJ_key_file_type_input_systemd : NMOBJ_key_file_type_input_stdin;
	  key.key_or_keyfile_location = NULL;
	}
      } else if (starts_with(entities[i].key, "CLEVIS=") == true) {
	char  *exec_dir[]     = {"/usr/bin", "/bin", "/sbin", "/usr/sbin", "~/local/bin", NULL};
	char  *dup_stdout     = NULL;
	size_t dup_stdout_len = 0;
	int    exec_ret_val   = 0;
	bool   success;

	int key_fd_in = open(entities[i].key + strlen("CLEVIS="), O_RDONLY);
	if (key_fd_in == -1) {
	  switch (errno) {
	  case ENOENT: print_error(_("Clevis file %s does not exist."), entities[i].key + strlen("CLEVIS="));
	  case EACCES: print_error(_("invalid permission to open clevis file. Are you root?"));
	  }
	}

	success = exec_name("clevis", exec_dir, key_fd_in, &dup_stdout, &dup_stdout_len, &exec_ret_val, NMOBJ_exec_name_wait_child,
			    "decrypt", NULL);
	if (success == false) {
	  if (errno == ENOENT) {
	    print_error(
                        _("clevis not found. it must reside under \"/usr/bin\", \"/bin\", \"/sbin\", \"/usr/sbin\" or \"~/local/bin\""));
	  } else {
	    print_error(_("cannot invoke clevis: %s"), strerror(errno));
	  }
	} else if (exec_ret_val != 0) {
	  print_error(_("cannot extract key from clevis: %s"), dup_stdout);
	}
	close(key_fd_in);
	if (master_key_to_byte_array(dup_stdout, (uint8_t *) key_raw) == false) {
	  print_error(_("error when parsing clevis: invalid format. Is this the right key?"));
	};
	key.key_or_keyfile_location = (char *) key_raw;
	key.key_type                = NMOBJ_key_file_type_key_raw;
	free(dup_stdout);
      } else {
	key.key_or_keyfile_location = entities[i].key + strlen("KEYFILE=");
	key.key_type                = NMOBJ_key_file_type_file;
      }

      action_open(
		  STR_device->name, entities[i].to, 0, key, master_key,
		  HAS_FLGI(NMOBJ_windhamtab_max_unlock_mem) ? entities[i].max_unlock_mem : max_unlock_mem,
		  HAS_FLGI(NMOBJ_windhamtab_max_unlock_time) ? entities[i].max_unlock_time : max_unlock_time, 0, false, false, is_dry_run,
		  HAS_FLGI(NMOBJ_windhamtab_ro) || is_target_readonly,
		  HAS_FLGI(NMOBJ_windhamtab_target_allow_discards) || is_allow_discards,
		  HAS_FLGI(NMOBJ_windhamtab_no_read_wq) || is_no_read_workqueue,
		  HAS_FLGI(NMOBJ_windhamtab_no_write_wq) || is_no_write_workqueue,
		  HAS_FLGI(NMOBJ_windhamtab_is_no_map_partition), true);
#undef HAS_FLGI
    }

  } else {
    char * random_target_name;
    if (target_name == NULL) {
      random_target_name = alloca(strlen("windham-123e4567-e89b-12d3-a456-426614174000") + 1);
      memcpy(random_target_name, "windham-", strlen("windham-"));
      uint8_t random_bits[16];
      fill_secure_random_bits(random_bits, 16);
      generate_UUID_from_bytes(random_bits, random_target_name + strlen("windham-"));
    }
    init_device(uninit_device, is_dry_run == false, is_target_readonly, is_nofail, is_decoy);
    action_open(STR_device->name,
		target_name == NULL ? random_target_name : target_name,
		timeout, key, master_key, max_unlock_mem, max_unlock_time, max_unlock_level, is_allow_nolock,
		is_decoy, is_dry_run, is_target_readonly, is_allow_discards, is_no_read_workqueue, is_no_write_workqueue, is_no_map_partition,
		is_nokeyring);
  }
}
