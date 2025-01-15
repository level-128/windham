#pragma once

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../library_intrnlsrc/mapper.c"
#include "../library_intrnlsrc/srclib.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "windham_const.h"


void action_close(const char * device, bool is_deferred_remove) {

#define STARTSWITH(str, prefix) (strlen(str) >= strlen(prefix) && strncmp((str), (prefix), strlen(prefix)) == 0)
  
  if (device[0] != '/'){
  
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
   CHECK_DEVICE_TOPOLOGY(
      device,
      "/dev/mapper",
      child,
      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
         mount_points_len, > 0, mount_points,
         (_("Cannot close device %s, device has been mounted at %s. Unmount the device to continue"), device, mount_points[0]),
         (_("Cannot close device %s, unmount the device to continue. Active mount points:"), device));

      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(parent_ret_len, > 1, parent,
         (_("The associate device %s has multiple childs. This is likely because the partition mapping "
               "scheme has been modified since last setup. Windham can not close this device."),
            device),
         ("")));
   CHECK_DEVICE_TOPOLOGY_FREE(parent);
#pragma GCC diagnostic pop
   remove_crypt_mapping(device, is_deferred_remove);
  } else {
    if (STARTSWITH(device, "/dev/mapper/")){
      print_error(_("The provided name is a mapped block device, use \"Windham Close %s\" to close the device."),  device + strlen("/dev/mapper/"));
    }
    else if(STARTSWITH(device, "/dev/")){

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
   CHECK_DEVICE_TOPOLOGY(
      device,
      "",
      parent,
      do {
	if (child_ret_len == 1 && STARTSWITH(child[0], "/dev/mapper/")){
	  ask_for_conformation(_("The provided name is a raw block device before the device mapper target. "
			       "Do you mean to close the device with name \"%s\"?"),
			       child[0] + strlen("/dev/mapper/"));
	  remove_crypt_mapping( child[0] + strlen("/dev/mapper/"), is_deferred_remove);
	} else if (child_ret_len >= 1){
	  print_error(_("The provided name is a raw block device, however it is not used as a Windham partition. Use \"lsblk\" "
			"or \"ls -l\" to search for the correct Windham partition name. "
			"Also, %s has mutiple mappings, so it might be a disk with partition table or a LVM device. This means it is not what you looking for."),
		      device);
	} else {
	  print_error(_("The provided name is a raw block device, however it is not used as a Windham partition. Use \"lsblk\" "
			"or \"ls -l\" to search for the correct Windham partition name."));
	}
      } while(0);
      );
   CHECK_DEVICE_TOPOLOGY_FREE(child);
#pragma GCC diagnostic pop
    }
    print_error(_("The device name is required, however path is provided. Use \"lsblk\" or \"ls -l\" to search for the correct device."));
  }
}


int action_addkey(
   const char * device,
   PARAMS_FOR_KEY,
   uint64_t   target_memory,
   double     target_time,
   const int  target_level,
   const bool is_no_detect_entropy,
   const bool is_random_key_stdout,
   const bool is_rapid_add,
   const bool is_anonymous_key) {
  Data                      data;
  int64_t                   offset;
  Key                       new_key;
  int                       ret_target_level;
   
  const ENUM_MAPPER_DEVSTAT device_stat = locate_possible_header_location_and_type(device, &data, &offset, is_decoy);
  if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
    print_error(_("The header is suspended. Resume header to perform this operation."));
  }

  OPERATION_BACKEND_UNENCRYPT_HEADER

    if (is_random_key_stdout == false) {
      action_addkey_interactive_prepare_key(&new_key);

      add_key_to_keyslot(
			 &data,
			 master_key,
			 new_key,
			 device,
			 target_memory,
			 target_time,
			 target_level,
			 is_no_detect_entropy,
			 is_rapid_add,
			 is_anonymous_key,
			 is_allow_nolock,
			 &ret_target_level);
    } else { // is_random_key_stdout == true
      uint8_t new_key_uint8[HASHLEN];
      fill_secure_random_bits(new_key_uint8, HASHLEN);
      new_key.key_type                = NMOBJ_key_file_type_key_raw;
      new_key.key_or_keyfile_location = (char *) new_key_uint8;

      add_key_to_keyslot(
			 &data,
			 master_key,
			 new_key,
			 device,
			 target_memory,
			 target_time,
			 target_level,
			 is_no_detect_entropy,
			 is_rapid_add,
			 is_anonymous_key,
			 is_allow_nolock,
			 &ret_target_level);
      // print the new_key_uint8 to the real stdout
      for (size_t i = 0; i < HASHLEN; ++i) {
	char print_buf[4];
	sprintf(print_buf, "%02x ", new_key_uint8[i]);
	if (write(stdout_fd, print_buf, 3) != 3){
	  // stdout blocked, not process group leader?
	  printk("Cannot print key to stdout: write failed.");
	  windham_exit(1);
	};
      }

   }

   OPERATION_LOCK_AND_WRITE
   return 0;
}

#include <stdio.h> 

void action_removekey(
		      const char * device,
		      PARAMS_FOR_KEY,
		      const bool is_make_anonymous,
		      const bool is_no_fill_random_pattern
		      ) {
  Data data;
  int64_t                   offset;

  const ENUM_MAPPER_DEVSTAT device_stat = locate_possible_header_location_and_type(device, &data, &offset, is_decoy);
  if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
    print_error(_("The header is suspended. Resume header to perform this operation."));
  }

  OPERATION_BACKEND_UNENCRYPT_HEADER

  if (is_make_anonymous == false){
    int key_count = 0;
    for (int i = 0; i < KEY_SLOT_COUNT; i++){
      key_count += data.metadata.keyslot_level[i] != 0;
    }
    if (key_count == 1){
      ask_for_conformation(_("You are trying to remove the last password. You should not proceed unless you have already backed up "
			     "your master key."));
    }
  }
  
  // TODO print warning when revokeing the last key
  if (is_no_fill_random_pattern == false){
    fill_random_pattern_in_keypool(&data);
  }

  // overwrite keypool
  if (is_make_anonymous == false){
    int target_size = convert_stage_to_size(ret_level);
    uint64_t random_value;
    fill_secure_random_bits((uint8_t *)&random_value, sizeof(random_value));
    random_value %= target_size - PATTERN_LEN; // make sure the boundaries fit within target
    fill_secure_random_bits(&data.keypool[ret_key_zone].keypool[random_value + ret_key_location], PATTERN_LEN);
  }
   
  for (size_t i = 0; i < KEY_SLOT_COUNT; ++i) {
    if (data.metadata.keyslot_level[i] == ret_level && data.metadata.keyslot_location[i] == ret_key_location) {
      if (GET_BIT(data.metadata.keyslot_location_area, i) == ret_key_zone) {
	if (is_make_anonymous){ // an anonymous key has keyslot_level != 0 while stored key is 0
	  data.metadata.keyslot_location[i] = 0;
	  memset(data.metadata.keyslot_key[i], 0, HASHLEN);
	} else {
	  data.metadata.keyslot_level[i] = 0;
	  data.metadata.keyslot_location[i] = 0;
	  fill_secure_random_bits(data.metadata.keyslot_key[i],  HASHLEN);
	}
	goto LOCK_AND_WRITE;
      }
    }
  }
  if (is_make_anonymous){
    printf(_("The provided key is already stored anonymously. Nothing to do.\n"));
    windham_exit(0);
  } else {
    __builtin_trap();
  }
 LOCK_AND_WRITE:;
  OPERATION_LOCK_AND_WRITE
    }


void action_backup(const char * device, const char * filename, const bool is_decoy) {
  if (access(filename, F_OK) != -1) {
    print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);
  }

  Data                data;
  int64_t             offset;
  ENUM_MAPPER_DEVSTAT device_stat = locate_possible_header_location_and_type(device, &data, &offset, is_decoy);
  if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
    print_error(_("The header is suspended. Resume header to perform this operation. Although it is technically possible to backup a"
		  " suspended partition, You should not do this."));
  }

  write_header_to_device(&data, filename, 0);
}


void action_restore(const char * device, const char * filename, const bool is_decoy) {
  if (is_decoy) {
    ask_for_conformation(
			 _("Restoring header to device \"%s\" as decoy partition, All content will be lost. Continue?"),
			 device);
  } else {
    ask_for_conformation(_("Restoring header to device \"%s\", All content will be lost. Continue?"), device);
  }

  Data    data;
  int64_t offset;
  locate_possible_header_location_and_type(filename, &data, &offset, is_decoy);

  // TODO: print warning if user cannot unlock; Check is is_decoy and range valid before restore.
  write_header_to_device(
			 &data,
			 device,
			 offset);
}


void action_suspend(const char * device, PARAMS_FOR_KEY) {
  Data    data;
  int64_t offset;
  locate_possible_header_location_and_type(device, &data, &offset, is_decoy);

  if (is_header_suspended(data)) {
    print_error(_("The device %s is already suspended."), device);
  }
  Data data_copy;
  memcpy(&data_copy, &data, sizeof(data_copy));
  OPERATION_BACKEND_UNENCRYPT_HEADER // get master key and validate

    suspend_encryption(&data_copy, master_key);
  write_header_to_device(&data_copy, device, offset);
}


void action_resume(const char * device, PARAMS_FOR_KEY) {
   Data    data;
   int64_t offset;

   locate_possible_header_location_and_type(device, &data, &offset, is_decoy);

   if (! is_header_suspended(data)) {
      print_error(_("The device %s is not suspended."), device);
   }
   Data data_copy;
   memcpy(&data_copy, &data, sizeof(data_copy));
   // unlock the header but not validate key using metadata. metadata is a mess right now.
   int _, __;
   uint16_t ___;
   get_master_key(data, master_key, key, device, max_unlock_mem, max_unlock_time, max_unlock_level, is_allow_nolock, &_, &__, &___);

   if (resume_encryption(&data_copy, master_key) == false) {
      print_error(_("The header is likely damaged, or is has been tampered. Modifying the header, even if some of the "
		    "contents in metadata zone are recorded in plain text during suspend, is considered as an erroneous operation "
		    "by design. Windham is crafted and designed to forbid such operation, and it is impossible to restore the header "
		    "that differs from the suspended one who has run into an unsupported state. You have unlimited access to the "
		    "suspended Windham partition; you should migrate your file to a new partition instead."));
   };
   write_header_to_device(&data_copy, device, (int64_t) offset);
}

void action_destory(const char * device, bool is_decoy){
   Data    data;
   int64_t offset;

   ENUM_MAPPER_DEVSTAT stat = locate_possible_header_location_and_type(device, &data, &offset, is_decoy);

   uint8_t *uuid = data.uuid_and_salt;
   printf(_("Removing device with UUID: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"),
	  uuid[0],
            uuid[1],
            uuid[2],
            uuid[3],
            uuid[4],
            uuid[5],
            uuid[6],
            uuid[7],
            uuid[8],
            uuid[9],
            uuid[10],
            uuid[11],
            uuid[12],
            uuid[13],
            uuid[14],
            uuid[15]);
   printf(_("The header offset is located at sector %"PRIu64", This area will be wipped and it is almost impossible "
		   "to recover.\nYou cannot regain access even using your master key. It is highly suggest to also "
		   "remove your backup created using \"windham Backup\". If you have used \"windham Open\" with \"--timeout\", "
		   "There is a copy of the raw key resides in the Linux kernel, restarting the system or wait until timeout to"
	    " delete it.\n"), offset);
   
   if (stat == NMOBJ_MAPPER_DEVSTAT_SUSP){
     print_warning(_("The partition is suspended. destorying a suspended partition does not equal to decrypt the partition."));
   }
      ask_for_conformation("");

   int fd = open(device, O_RDWR);
   for (int i = 0; i < 3; i++){
     fill_secure_random_bits((uint8_t *)&data, sizeof(Data));
     lseek(fd, SEEK_SET, 0);
     if (write(fd, &data, sizeof(Data)) != sizeof(Data)){
       if (errno == ENOSPC){
	 print_error(_("No free space. Copy on Write or de-dup filesystem?"));
       } else if (errno == EIO){
	 print_warning(_("IO error while wiping the header during attempt %i, bad physical device?"), i);
       } else if (errno == EINTR){
	 i --;
       }
     }
     fsync(fd);
     sleep(1);
   }
   close(fd);
}
