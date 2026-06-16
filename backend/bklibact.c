#pragma once

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../libsrc/mapper.c"
#include "../libsrc/srclib.c"
#include "../libplat/get_entropy.c"
#include "../libplat/loopctl.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "../include/windham_const.h"


void action_close(const char * device, bool is_deferred_remove) {
#define STARTSWITH(str, prefix) (strlen(str) >= strlen(prefix) && strncmp((str), (prefix), strlen(prefix)) == 0)

   if (device[0] != '/') {
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
            (_("The associate device %s has multiple children. This is likely because the partition mapping "
                  "scheme has been modified since last setup. Windham can not close this device."),
               device),
            ("")));
      CHECK_DEVICE_TOPOLOGY_FREE(parent);
      remove_crypt_mapping(device, is_deferred_remove);
   } else {
      // device[0] == '/'
      if (STARTSWITH(device, "/dev/mapper/")) {
         print_error(
            _("The provided name is a mapped block device, use \"Windham Close %s\" to close the device."),
            device + strlen("/dev/mapper/"));
      } else if (STARTSWITH(device, "/dev/")) {
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
                  "Also, %s has mutiple mappings, so it might be a disk with partition table or a LVM device. This means it is not what you looking for."
               ),
               device);
            } else {
            print_error(_("The provided name is a raw block device, however it is not used as a Windham partition. Use \"lsblk\" "
               "or \"ls -l\" to search for the correct Windham partition name."));
            }
            } while(0);
         );
         CHECK_DEVICE_TOPOLOGY_FREE(child);
         return;
#pragma GCC diagnostic pop
      }
      print_error(
         _("The device name is required, however path is provided. Use \"lsblk\" or \"ls -l\" to search for the correct device."
         ));
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
   Data    data;
   int64_t offset;
   Key     new_key;
   int     ret_target_level;

   const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy);
   if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
      print_error(_("The header is suspended. Resume header to perform this operation."));
   }

   OPERATION_BACKEND_UNENCRYPT_HEADER

   if (is_random_key_stdout == false) {
      action_addkey_interactive_prepare_key(&new_key);
   } else { // is_random_key_stdout == true
      uint8_t new_key_uint8[HASHLEN];
      fill_secure_random_bits(new_key_uint8, HASHLEN);
      new_key.key_type                = NMOBJ_key_file_type_key_raw;
      new_key.key_or_keyfile_location = (char *) new_key_uint8;
      // print the new_key_uint8 to the real stdout
#ifndef WINDHAM_ISOC
      for (size_t i = 0; i < HASHLEN; ++i) {
         char print_buf[4];
         sprintf(print_buf, "%02x ", new_key_uint8[i]);
         if (write(stdout_fd, print_buf, 3) != 3) {
            // stdout blocked, not process group leader?
            printk("Cannot print key to stdout: write failed.");
            windham_exit(1);
         };
      }
#else // Under ISO C, output is not redirect to stderr. print the key to the terminal.
   printf(_("Random generated Key: "));
      print_hex_array(HASHLEN, new_key_uint8);
      printf(_("Copy the key to somewhere else and clear this terminal."));
#endif
   }

   // Save old master_key_mask before add_key_to_keyslot potentially changes it 
   uint8_t old_master_key_mask[HASHLEN];
   if (is_rapid_add == false) {
      memcpy(old_master_key_mask, data.master_key_mask, HASHLEN);
   }

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

   // Non-rapid add: master_key_mask changed, re-encrypt aux zone with new IV 
   if (is_rapid_add == false) {
      size_t aux_zone_size = 0;
      uint8_t *aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);
      if (aux_zone_size != 0) {
         uint8_t aux_key[HASHLEN];
         get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.aux_key_mask, data.uuid_and_salt, aux_key);
         if (!decrypt_aux_zone(aux_zone, aux_zone_size, aux_key, old_master_key_mask)) {
            print_warning(_("Aux zone cannot be decrypted with old header IV; aux data may be lost."));
         }
         encrypt_aux_zone(aux_zone, aux_zone_size, aux_key, data.master_key_mask);
         write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
      }
      free(aux_zone);
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
   Data    data;
   int64_t offset;

   const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy);
   if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
      print_error(_("The header is suspended. Resume header to perform this operation."));
   }

   OPERATION_BACKEND_UNENCRYPT_HEADER

   if (is_make_anonymous == false) {
      int key_count = 0;
      for (int i = 0; i < KEY_SLOT_COUNT; i ++) {
         key_count += data.metadata.keyslot_level[i] != 0;
      }
      if (key_count == 1) {
         ask_for_conformation(
            _(
               "You are trying to remove the last password. You should not proceed unless you have already backed up "
               "your master key."));
      }
   }

   /* Probe aux zone for non-public entries belonging to the key being deleted */
   bool has_aux_to_delete = false;
   if (!is_make_anonymous && memcmp(ret_inited_key, (uint8_t[HASHLEN]){0}, HASHLEN) != 0) {
      size_t  aux_zone_size = 0;
      uint8_t *aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);
      if (aux_zone_size != 0 && decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
         uint32_t pointer = 0;
         int count = 0;
         while (true) {
            bool is_public = false;
            uint32_t slot_offset = 0;
            AuxSlot *slot = probe_aux_from_aux_zone(aux_zone, aux_zone_size, &pointer, ret_inited_key, &is_public, &slot_offset);
            if (slot == NULL) break;
            if (!is_public) {
               if (count == 0) {
                  printf(_("The following aux entries are associated with the key being deleted:\n"));
               }
               count++;
               print_aux_entry(slot, slot_offset, false, count);
               has_aux_to_delete = true;
            }
            free(slot);
         }
         if (has_aux_to_delete) {
            ask_for_conformation(_("Remove these aux entries?"));
            remove_aux_from_aux_zone_by_key(aux_zone, aux_zone_size, ret_inited_key);
            encrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key);
            write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
         }
      }
      free(aux_zone);
   }

   if (is_no_fill_random_pattern == false) {
      fill_random_pattern_in_keypool(&data);
   }

   // overwrite keypool
   if (is_make_anonymous == false) {
      int      target_size = convert_stage_to_size(ret_level);
      uint64_t random_value;
      fill_secure_random_bits((uint8_t *) &random_value, sizeof(random_value));
      random_value %= target_size - PATTERN_LEN;
      fill_secure_random_bits(&data.keypool[ret_key_zone].keypool[random_value + ret_key_location], PATTERN_LEN);
   }

   for (size_t i = 0; i < KEY_SLOT_COUNT; ++i) {
      if (data.metadata.keyslot_level[i] == ret_level && data.metadata.keyslot_location[i] == ret_key_location) {
         if (GET_BIT(data.metadata.keyslot_location_area, i) == ret_key_zone) {
            if (is_make_anonymous) {
               data.metadata.keyslot_location[i] = 0;
               memset(data.metadata.keyslot_key[i], 0, HASHLEN);
            } else {
               data.metadata.keyslot_level[i]    = 0;
               data.metadata.keyslot_location[i] = 0;
               fill_secure_random_bits(data.metadata.keyslot_key[i], HASHLEN);
            }
            goto LOCK_AND_WRITE;
         }
      }
   }
   if (is_make_anonymous) {
      printf(_("The provided key is already stored anonymously. Nothing to do.\n"));
      windham_exit(0);
   } else {
      exit(2);
   }

LOCK_AND_WRITE:;
   OPERATION_LOCK_AND_WRITE
}


void action_backup(const char * device, char * filename, const bool is_decoy, const bool is_qrcode) {
   (void)is_qrcode;
   if (filename == NULL) {
      filename = "windham_backup";
   }

   printf(_("Creating header backup for device %s to %s\n"), device, filename);

#ifndef WINDHAM_ISOC
   if (access(filename, F_OK) != -1) {
      print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);
   }
#else
   FILE *file = fopen(filename, "r");
   if (file != NULL) {
      fclose(file);
      print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);
   }
#endif

   Data                data;
   int64_t             offset;
   ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy);
   if (device_stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
      print_error(
         _("The header is suspended. Resume header to perform this operation. Although it is technically possible to backup a"
            " suspended partition, You should not do this."));
   }

#ifndef WINDHAM_ISOC
   int fd = creat(filename, S_IRUSR);
   if (fd == -1) {
      print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
   }
   close(fd);
#else
   file = fopen(filename, "wb");
   if (file == NULL) {
      print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
   }
   fclose(file);
#endif

   write_header_to_device(&data, filename, 0);
}

void action_restore(const char * device, const char * filename, const bool is_decoy) {
   Data    data;
   int64_t offset = 0;

   if (is_decoy) {
      ask_for_conformation(
         _("Restoring header to device \"%s\" as decoy partition. The header offset of the decoy partition is based on "
           "the current layout of the device, which might differ from the original layout. Restore to a mismatched "
           "layout will DESTROY your data! Confirm no change has been made between backup and restore."),
         device);

   } else {
      ask_for_conformation(_("Restoring header to device \"%s\", Continue?"), device);

      load_header_by_device(filename, &data, &offset, false);
   }


   write_header_to_device(
      &data,
      device,
      offset);
}


void action_suspend(const char * device, PARAMS_FOR_KEY) {
   Data    data;
   int64_t offset;

   load_header_by_device(device, &data, &offset, is_decoy);

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

   load_header_by_device(device, &data, &offset, is_decoy);

   if (! is_header_suspended(data)) {
      print_error(_("The device %s is not suspended."), device);
   }
   Data data_copy;
   memcpy(&data_copy, &data, sizeof(data_copy));
   // unlock the header but not validate key using metadata. metadata is a mess right now.
   unsigned _, __;
   uint16_t ___;
   uint8_t ____[HASHLEN];
   get_master_key(
      data,
      master_key,
      key,
      device,
      max_unlock_mem,
      max_unlock_time,
      max_unlock_level,
      is_allow_nolock,
      &_,
      &__,
      &___,
      ____);

   if (resume_encryption(&data_copy, master_key) == false) {
      print_error(
         _("The header is likely damaged, or is has been tampered. Modifying the header, even if some of the "
            "contents in metadata zone are recorded in plain text during suspend, is considered as an erroneous operation "
            "by design. Windham is crafted and designed to forbid such operation, and it is impossible to restore the header "
            "that differs from the suspended one who has run into an unsupported state. You have unlimited access to the "
            "suspended Windham partition; you should migrate your file to a new partition instead."));
   };
   write_header_to_device(&data_copy, device, (int64_t) offset);
}

void action_destory(const char * device, bool is_decoy) {
   Data    data;
   int64_t offset;

   ENUM_MAPPER_DEVSTAT stat = load_header_by_device(device, &data, &offset, is_decoy);

   uint8_t * uuid = data.uuid_and_salt;
   printf(
      _("Removing device with UUID: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"),
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
   printf(
      _(
         "The header offset is located at sector %"PRIu64", This area will be wipped and it is almost impossible "
         "to recover.\nYou cannot regain access even using your master key. It is highly suggest to also "
         "remove your backup created using \"windham Backup\". If you have used \"windham Open\" with \"--timeout\", "
         "There is a copy of the raw key resides in the Linux kernel, restarting the system or wait until timeout to"
         " delete it.\n"),
      offset);

   if (stat == NMOBJ_MAPPER_DEVSTAT_SUSP) {
      print_warning(_("The partition is suspended. destorying a suspended partition does not equal to decrypt the partition."));
   }
   ask_for_conformation("");

   // wipe the disk
   FILE* fp = fopen(device, "r+b");
   if (!fp) {
      print_error(_("Failed to wipe device: %s"), strerror(errno));
   }
   setvbuf(fp, NULL, _IONBF, 0);


   for (int i = 0; i < 3; i++) {
      fill_secure_random_bits((uint8_t*)&data, sizeof(Data));

      if (fseek(fp, 0, SEEK_SET) != 0) {
         perror("fseek failed");
         exit(2);
      }

      size_t written = fwrite(&data, sizeof(Data), 1, fp);
      if (written != 1) {
         if (ferror(fp)) {
            print_error(_("Failed to write device during wipe: %s"), strerror(errno));
         }
      }

      if (fflush(fp) != 0) {
         perror("fflush failed");
         exit(2);
      }

      // sync the disk.
#ifndef WINDHAM_ISOC
      sync();
#endif

      // depends on target.
#ifndef WINDHAM_ISOC
      sleep(1);
#elif defined(__STDC_NO_THREADS__)
      struct timespec start, current;

      if (timespec_get(&start, TIME_UTC) != TIME_UTC) {
         perror("Failed to get start time");
         return;
      }

      int64_t elapsed_ns = 0;
      do {
         if (timespec_get(&current, TIME_UTC) != TIME_UTC) {
            perror("Failed to get current time");
            return;
         }
         elapsed_ns = (current.tv_sec - start.tv_sec) * 1000000000LL;
         elapsed_ns += (current.tv_nsec - start.tv_nsec);
      } while (elapsed_ns < 1000000000);
#else
      thrd_sleep(&(struct timespec){.tv_sec=1}, NULL);
#endif
   }

   fclose(fp);
}
