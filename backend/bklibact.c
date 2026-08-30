#ifndef INCL_BKLIBACT
#define INCL_BKLIBACT

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../include/QRCode.h"

#include "../libsrc/mapper.c"
#include "../libsrc/srclib.c"
#include "../libsrc/libbmp.c"
#include "../libplat/get_entropy.c"
#include "../libplat/loopctl.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "../include/windham_const.h"


void action_close(const char * device, bool is_deferred_remove) {
#define STARTSWITH(str, prefix) (strlen(str) >= strlen(prefix) && strncmp((str), (prefix), strlen(prefix)) == 0)

    if (!current_driver || !current_driver->remove) {
        print_warning(_("cannot close %s: no driver loaded."), device);
        return;
    }

    if (device[0] != '/') {
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-zero-length"
#endif
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
      if (STARTSWITH(device, "/dev/")) {
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
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
      }
      print_error(
         _("The device name is required, however path is provided. Use \"lsblk\" or \"ls -l\" to search for the correct device."
         ));
    }
}

void action_close_all(bool is_deferred_remove) {
#ifdef WINDHAM_PLAT_GNU_LINUX
#include <dirent.h>
    if (!current_driver || !current_driver->remove) {
        print_warning(_("cannot close: no driver loaded."));
        return;
    }
    DIR *dir = opendir("/dev/mapper");
    if (!dir) {
        print_error(_("Cannot open /dev/mapper to list devices."));
    }

    struct dirent *ent;
    int closed = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "windham-", 8) != 0) continue;
        if (strcmp(ent->d_name, "control") == 0) continue;

        printf(_("Closing %s... "), ent->d_name);
        remove_crypt_mapping(ent->d_name, is_deferred_remove);
        printf(_("OK\n"));
        closed++;
    }
    closedir(dir);
    if (closed > 0) {
        printf(_("Closed %d windham device(s).\n"), closed);
    } else {
        printf(_("No active Windham devices found.\n"));
    }
#else
    (void)is_deferred_remove;
    print_error(_("--all is not available in ISO C mode."));
#endif
}

#ifndef CFG_TARGET_READONLY
int action_addkey(
   const char * device,
   PARAMS_FOR_KEY,
   uint64_t   target_memory,
   double     target_time,
   const int  target_level,
   const bool is_no_detect_entropy,
   const bool is_random_key_stdout,
   const bool is_rapid_add,
   const bool is_anonymous_key,
   const char * new_key_password) {
   Data    data;
   int64_t offset;
   Key     new_key;
   int     ret_target_level;

   const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

   OPERATION_BACKEND_UNENCRYPT_HEADER

    if (is_random_key_stdout == false) {
       if (new_key_password != NULL) {
          // --new-key=<value>: use the passphrase non-interactively
          new_key.key_type                = NMOBJ_key_file_type_key;
          new_key.key_or_keyfile_location = (char *)new_key_password;
       } else {
          action_addkey_interactive_prepare_key(&new_key);
       }
    } else { // is_random_key_stdout == true
       uint8_t new_key_uint8[HASHLEN];
       fill_secure_random_bits(new_key_uint8, HASHLEN);
       // Encode as 64-character hex string -- behaves like a normal --key=<value> password
       static char rand_key_hex[HASHLEN * 2 + 1];
       for (size_t i = 0; i < HASHLEN; i++) {
          sprintf(rand_key_hex + i * 2, "%02x", new_key_uint8[i]);
       }
       rand_key_hex[HASHLEN * 2] = '\0';
       new_key.key_type                = NMOBJ_key_file_type_key;
       new_key.key_or_keyfile_location = rand_key_hex;
#ifdef WINDHAM_PLAT_GNU_LINUX
       // Print to stdout as a single hex string (no spaces), suitable for --target-key
       if (write(stdout_fd, rand_key_hex, HASHLEN * 2) != (ssize_t)HASHLEN * 2) {
          printf("Cannot print key to stdout: write failed.\n");
          windham_exit(1);
       }
       if (write(stdout_fd, "\n", 1) != 1) { /* ignore */ }
#else
       printf("Random generated Key: %s\n", rand_key_hex);
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
          get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.aux_key_mask, data.uuid_and_salt, aux_key, HASHLEN);
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
#endif // #ifndef CFG_TARGET_READONLY


#ifndef CFG_TARGET_READONLY
void action_removekey(
   const char * device,
   PARAMS_FOR_KEY,
   const bool is_make_anonymous,
   const bool is_no_fill_random_pattern
) {
   Data    data;
   int64_t offset;

   const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

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
#endif // #ifndef CFG_TARGET_READONLY


void action_backup(const char * device, char * filename, const bool is_decoy, const bool is_qrcode, const char * qrcode_path, bool is_fold, const Key key, uint8_t master_key_input[HASHLEN]) {
   uint8_t qrdata[sizeof(Key_slot) + (offsetof(Data, keypool) - offsetof(Data, uuid_and_salt))];
   size_t  qrlen = sizeof(qrdata);

   if (is_qrcode){
      is_fold = true;
   }

   if (is_fold) {
      /* Do a fold backup from device to memory */
      Data     data;
      int64_t  offset;
      load_header_by_device(device, &data, &offset, is_decoy, false);

      unsigned ret_key_zone, ret_level;
      uint16_t ret_key_location;
      uint8_t  ret_inited_key[HASHLEN];
      bool     is_mk = (key.key_type == NMOBJ_key_file_type_masterkey);

      get_master_key(data, master_key_input, key, device,
                     SIZE_MAX, DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                     KEY_SLOT_EXP_MAX, false,
                     &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);
      unlock_metadata_using_master_key(&data, master_key_input);
      memset(data.metadata.keyslot_key,      0, sizeof(data.metadata.keyslot_key));
      memset(data.metadata.keyslot_level,    0, sizeof(data.metadata.keyslot_level));
      memset(data.metadata.keyslot_location, 0, sizeof(data.metadata.keyslot_location));
      data.metadata.keyslot_location_area = 0;
      if (is_mk) {
         /* Master-key backup: header metadata only. The password keyslot
            material is not included, so the Key_slot area of the backup is
            random filler — byte-for-byte indistinguishable from a password
            backup. Restoring it yields a disk that unlocks with the master
            key alone; slot 0 stays empty. */
         fill_secure_random_bits(qrdata, sizeof(Key_slot));
      } else {
         /* Password backup: keep the matched keyslot alive. qrdata carries
            the raw Key_slot (hash salt + key mask); metadata slot 0 records
            the inited key / level / location so the restored disk can be
            unlocked with the same password — or with the master key. */
         memcpy(qrdata, get_slot_loc(data, ret_key_zone, ret_key_location), sizeof(Key_slot));
         memcpy(data.metadata.keyslot_key[0], ret_inited_key, HASHLEN);
         data.metadata.keyslot_level[0] = ret_level;
         data.metadata.keyslot_location[0] = ret_key_location;
         data.metadata.keyslot_location_area = ret_key_zone; // 0 or 1, to the first bit.
      }
      /* Re-encrypt metadata — QR must contain ciphertext */
      lock_metadata_using_master_key(&data, master_key_input);
      memcpy(qrdata + sizeof(Key_slot), data.uuid_and_salt,
               offsetof(Data, keypool) - offsetof(Data, uuid_and_salt));
   } else {
      /* ======= ALL MODE: raw header dump ======= */
      if (filename == NULL) {
         filename = "windham_backup";
      }
      printf(_("Creating header backup for device %s to %s\n"), device, filename);
      if (device_is_exist(filename))
         print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);

      Data                alldata;
      int64_t             alloffset;
      ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &alldata, &alloffset, is_decoy, false);
      (void) device_stat;

      void *out = device_create(filename);
      if (!out)
         print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
      if (device_write(out, &alldata, sizeof(Data)) != (int64_t)sizeof(Data))
         print_error(_("Failed to write backup %s"), filename);
      device_close(out);
      printf("BACKUP_DONE\n");
      fflush(stdout);
      return;
   }
   if (is_qrcode) {
      /* Encode to QR code — auto-select minimum version */
      uint8_t  version = qrcode_getMinimumVersion((uint16_t)qrlen, ECC_MEDIUM);
      if (!version) print_error(_("QR encoding failed — data too large"));
      uint16_t buf_sz  = qrcode_getBufferSize(version);
      uint8_t *modules = malloc(buf_sz);
      if (!modules) { perror("malloc"); exit(1); }

      QRCode qr;
      if (qrcode_initBytes(&qr, modules, version, ECC_MEDIUM, qrdata, (uint16_t)qrlen) != 0)
         print_error(_("QR encoding failed — data too large"));

      /* Output */
      if (qrcode_path && qrcode_path[0] != '\0') {
         if (bmp_write(qrcode_path, &qr) != 0)
            print_error(_("QR code export to %s failed"), qrcode_path);
         printf(_("QR code saved to %s\n"), qrcode_path);
      } else {
         qr_print_terminal(&qr, init_val->is_color_print);
      }
      free(modules);
      printf("BACKUP_DONE\n");
      fflush(stdout);
      return;
   } else {
      /* Fold backup to file: Key_slot + uuid_and_salt..metadata */
      if (filename == NULL) {
         filename = "windham_backup";
      }
      printf(_("Creating header backup for device %s to %s\n"), device, filename);
      if (device_is_exist(filename))
         print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);

      void *out = device_create(filename);
      if (!out)
         print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
      if (device_write(out, qrdata, qrlen) != (int64_t)qrlen)
         print_error(_("Failed to write backup %s"), filename);
      device_close(out);
      printf("BACKUP_DONE\n");
      fflush(stdout);
   }


}


#ifndef CFG_TARGET_READONLY
void action_restore(const char * device, const char * filename, const bool is_decoy, const bool is_fold, const Key key, const uint8_t master_key_input[HASHLEN]) {
   if (is_fold) {
      /* ======= FOLD MODE RESTORE ======= */
      FILE *in = fopen(filename, "rb");
      if (!in) print_error(_("Cannot open fold backup file %s: %s"), filename, strerror(errno));

      /* 1. Read fold backup: Key_slot (144 B) + uuid_and_salt..metadata (816 B) */
      uint8_t ks_buf[sizeof(Key_slot)];
      if (fread(ks_buf, 1, sizeof(ks_buf), in) != sizeof(ks_buf))
         print_error(_("Fold backup file %s is too short"), filename);

      size_t meta_len = offsetof(Data, keypool) - offsetof(Data, uuid_and_salt);
      uint8_t *backup_meta = malloc(meta_len);
      if (!backup_meta) { perror("malloc"); exit(1); }
      if (fread(backup_meta, 1, meta_len, in) != meta_len)
         print_error(_("Fold backup file %s is too short"), filename);
      fclose(in);

      /* 2. Build the new header: random everywhere, then overlay the backup
            region (uuid/salt, mask, master key check, encrypted metadata). */
      uint8_t inited_key[HASHLEN];
      uint8_t master_key[HASHLEN];
      bool is_mk = (key.key_type == NMOBJ_key_file_type_masterkey);

      Data newdata;
      fill_secure_random_bits((uint8_t *)&newdata, sizeof(Data));
      memcpy(newdata.uuid_and_salt, backup_meta, meta_len);

      /* Random placement values are always drawn so that both backup kinds
         are indistinguishable by entropy consumption. */
      uint16_t volatile rnd_loc;
      fill_secure_random_bits((uint8_t *)&rnd_loc, sizeof(rnd_loc));
      uint8_t volatile rnd_zone;
      fill_secure_random_bits((uint8_t *)&rnd_zone, 1); rnd_zone %= 2;
      uint8_t zone_idx = rnd_zone;

      uint16_t keypool_loc;

      if (is_mk) {
         /* --- master key path: no KDF, decrypt the metadata directly --- */
         memcpy(master_key, master_key_input, HASHLEN);
         if (!check_master_key_check(newdata, master_key))
            print_error(_("Fold restore: master key check failed"));
         if (!unlock_metadata_using_master_key(&newdata, master_key))
            print_error(_("Fold restore: metadata decrypt failed"));
         /* The backup keeps the password slot at index 0: an all-zero
            keyslot_key[0] marks a master-key-only backup. */
         uint8_t zero[HASHLEN] = {0};
         if (memcmp(newdata.metadata.keyslot_key[0], zero, HASHLEN) == 0) {
            keypool_loc = rnd_loc % sizeof(Keypool);   /* random placement */
         } else {
            /* Password backup restored with the master key */
            memcpy(inited_key, newdata.metadata.keyslot_key[0], HASHLEN);
            keypool_loc = get_keypool_location_candidate(newdata.master_key_mask, inited_key);
         }
      } else {
         /* --- password path: place the slot, then derive via KDF ---
            A master-key backup restored with a password fails here: its
            Key_slot area is random filler, so no candidate matches. */
         prepare_key(key, inited_key, device, false);
         keypool_loc = get_keypool_location_candidate(newdata.master_key_mask, inited_key);
         memcpy(get_slot_loc(newdata, zone_idx, keypool_loc), ks_buf, sizeof(Key_slot));
         unsigned ret_zone, ret_level;
         int result = read_key_from_data(newdata, inited_key, keypool_loc,
                                         DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                                         SIZE_MAX, KEY_SLOT_EXP_MAX, false,
                                         &ret_zone, &ret_level, master_key);
         if (result != NMOBJ_Enclib_calc_okay)
            print_error(_("Fold restore: key derivation failed (error %d)"), result);
         if (!check_master_key_check(newdata, master_key))
            print_error(_("Fold restore: master key check failed"));
         if (!unlock_metadata_using_master_key(&newdata, master_key))
            print_error(_("Fold restore: metadata decrypt failed"));
      }

      /* 3. Place the Key_slot and point metadata slot 0 at it. The slot
            contents (keyslot_key[0] holds the backup's inited key) are
            already correct in the decrypted metadata. */
      memcpy(get_slot_loc(newdata, zone_idx, keypool_loc), ks_buf, sizeof(Key_slot));
      newdata.metadata.keyslot_level[0]    = 0;
      newdata.metadata.keyslot_location[0] = keypool_loc;
      newdata.metadata.keyslot_location_area = (uint64_t)zone_idx << 0;

      lock_metadata_using_master_key(&newdata, master_key);

      /* 4. Write to device */
      ask_for_conformation(_("Restoring fold backup to device \"%s\". Continue?"), device);
      write_header_to_device(&newdata, device, 0);
      printf(_("Fold restore complete.\n"));
      free(backup_meta);
      return;
   }

   /* ======= ALL MODE ======= */
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

      load_header_by_device(filename, &data, &offset, false, true);
   }


   write_header_to_device(
      &data,
      device,
      offset);
}
#endif // #ifndef CFG_TARGET_READONLY


#ifndef CFG_TARGET_READONLY
void action_suspend(const char * device, PARAMS_FOR_KEY) {
   Data    data;
   int64_t offset;

   load_header_by_device(device, &data, &offset, is_decoy, true);

   if (is_header_suspended(data)) {
      print_error(_("The device %s is already suspended."), device);
   }
   Data data_copy;
   memcpy(&data_copy, &data, sizeof(data_copy));
   OPERATION_BACKEND_UNENCRYPT_HEADER // get master key and validate

   suspend_encryption(&data_copy, master_key);
   write_header_to_device(&data_copy, device, offset);
}
#endif // #ifndef CFG_TARGET_READONLY


#ifndef CFG_TARGET_READONLY
void action_resume(const char * device, PARAMS_FOR_KEY) {
   Data    data;
   int64_t offset;

   load_header_by_device(device, &data, &offset, is_decoy, true);

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
#endif // #ifndef CFG_TARGET_READONLY


#ifndef CFG_TARGET_READONLY
void action_destory(const char * device, bool is_decoy) {
   Data    data;
   int64_t offset;

   ENUM_MAPPER_DEVSTAT stat = load_header_by_device(device, &data, &offset, is_decoy, true);

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
#ifdef WINDHAM_PLAT_GNU_LINUX
      sync();
#endif

      // depends on target.
#ifdef WINDHAM_PLAT_GNU_LINUX
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
#endif // #ifndef CFG_TARGET_READONLY


void action_list(void) {
#ifdef WINDHAM_PLAT_GNU_LINUX
   if (!is_device_mapper_available) {
      print_error(_("Device mapper library is not available."));
   }

   int count;
   char **names = dm_list(&count);
   if (!names || count == 0) {
      printf(_("No device mapper devices found.\n"));
      free(names);
      return;
   }

   int shown = 0;
   for (int i = 0; i < count; i++) {
      if (strncmp(names[i], "windham-", 8) != 0) {
         free(names[i]);
         continue;
      }

      int32_t  open_count;
      bool     read_only;
      uint32_t target_count;
      if (!dm_info(names[i], &open_count, &read_only, &target_count)) {
         free(names[i]);
         continue;
      }

      char uuid[129] = {0};
      dm_get_uuid(names[i], uuid);

      printf("%s\n", names[i]);
      printf("  UUID:     %s\n", uuid[0] ? uuid : "(none)");
      printf("  State:    ACTIVE%s\n",
             read_only ? " (read-only)" : "");
      printf("  Open:     %d\n", open_count);

      /* deps */
      uint64_t deps[256];
      int dep_count;
      if (dm_get_deps(names[i], deps, &dep_count) && dep_count > 0) {
         printf("  Device:   %u:%u\n",
                (unsigned)(deps[0] >> 8), (unsigned)(deps[0] & 0xFF));
      }

      /* target table */
      uint64_t start, length;
      char ttype[16], params[512];
      if (dm_get_first_target(names[i], &start, &length, ttype, params, sizeof(params))) {
         printf("  Target:   %s\n", ttype);
         printf("  Sector:   %"PRIu64" + %"PRIu64"\n", start, length);
         if (strcmp(ttype, "crypt") == 0) {
            char *p = params;
            /* skip cipher */
            while (*p && *p != ' ') p++;
            if (*p) p++;
            /* skip key (don't print it) */
            while (*p && *p != ' ') p++;
            if (*p) p++;
            /* skip iv_offset */
            while (*p && *p != ' ') p++;
            if (*p) p++;
            /* skip device */
            while (*p && *p != ' ') p++;
            if (*p) p++;
            /* skip start_offset */
            while (*p && *p != ' ') p++;
            if (*p) printf("  Options:  %s\n", p + 1);
         }
      }

      free(names[i]);
      shown++;
   }
   free(names);

   if (shown == 0) {
      printf(_("No active Windham devices found.\n"));
   }
#else
   print_error(_("List is not available in ISO C mode."));
#endif
}

#endif