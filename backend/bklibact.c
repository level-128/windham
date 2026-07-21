#ifndef INCL_BKLIBACT
#define INCL_BKLIBACT

#ifdef WINDHAM_PLAT_GNU_LINUX
#include <dirent.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "QRCode.h"

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

#include <stdio.h>

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
#endif
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


void action_backup(const char * device, char * filename, const bool is_decoy, const bool is_qrcode, const char * qrcode_path, const bool is_fold, const Key key, const uint8_t master_key_input[HASHLEN]) {
   if (is_qrcode) {
      /* ======= QR CODE OUTPUT ======= */
      uint8_t qrdata[sizeof(Key_slot) + (offsetof(Data, keypool) - offsetof(Data, uuid_and_salt))];
      size_t  qrlen = sizeof(qrdata);

      if (device != NULL) {
         /* Do a fold backup from device to memory */
         Data     data;
         int64_t  offset;
         load_header_by_device(device, &data, &offset, is_decoy, false);

         uint8_t  master_key[HASHLEN];
         unsigned ret_key_zone, ret_level;
         uint16_t ret_key_location;
         uint8_t  ret_inited_key[HASHLEN];
         bool     is_mk = (key.key_type == NMOBJ_key_file_type_masterkey);

         if (is_mk) {
            memcpy(master_key, master_key_input, HASHLEN);
            get_master_key(data, master_key, key, device,
                           SIZE_MAX, DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                           KEY_SLOT_EXP_MAX, false,
                           &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);
            fill_secure_random_bits(qrdata, sizeof(Key_slot));
            /* Clear metadata */
            memset(data.metadata.keyslot_key,      0, sizeof(data.metadata.keyslot_key));
            memset(data.metadata.keyslot_level,    0, sizeof(data.metadata.keyslot_level));
            memset(data.metadata.keyslot_location, 0, sizeof(data.metadata.keyslot_location));
            data.metadata.keyslot_location_area = 0;
         } else {
            get_master_key(data, master_key, key, device,
                           SIZE_MAX, DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                           KEY_SLOT_EXP_MAX, false,
                           &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);
            /* Extract matched Key_slot */
            memcpy(qrdata, get_slot_loc(data, ret_key_zone, ret_key_location), sizeof(Key_slot));

            /* Trim metadata: keep matched slot, clear others */
            uint16_t orig_loc[KEY_SLOT_COUNT];
            uint8_t  orig_lvl[KEY_SLOT_COUNT];
            uint64_t orig_area = data.metadata.keyslot_location_area;
            memcpy(orig_loc, data.metadata.keyslot_location, sizeof(orig_loc));
            memcpy(orig_lvl, data.metadata.keyslot_level,   sizeof(orig_lvl));
            unsigned matched = 0;
            for (unsigned i = 0; i < KEY_SLOT_COUNT; i++) {
               if (orig_loc[i] == ret_key_location &&
                   GET_BIT(orig_area, i) == ret_key_zone) { matched = i; break; }
            }
            uint8_t  saved_key[HASHLEN];
            memcpy(saved_key, data.metadata.keyslot_key[matched], HASHLEN);
            memset(data.metadata.keyslot_key,      0, sizeof(data.metadata.keyslot_key));
            memset(data.metadata.keyslot_level,    0, sizeof(data.metadata.keyslot_level));
            memset(data.metadata.keyslot_location, 0, sizeof(data.metadata.keyslot_location));
            data.metadata.keyslot_location_area = (uint64_t)ret_key_zone << 0;
            memcpy(data.metadata.keyslot_key[0], saved_key, HASHLEN);
            data.metadata.keyslot_level[0]    = orig_lvl[matched];
            data.metadata.keyslot_location[0] = orig_loc[matched];
         }
         memcpy(qrdata + sizeof(Key_slot), data.uuid_and_salt,
                offsetof(Data, keypool) - offsetof(Data, uuid_and_salt));
      } else {
         /* Read existing fold backup file */
         if (filename == NULL)
            print_error(_("--qrcode without device requires --to <fold-backup-file>"));
         FILE *in = fopen(filename, "rb");
         if (!in) print_error(_("Cannot open fold backup %s: %s"), filename, strerror(errno));
         if (fread(qrdata, 1, qrlen, in) != qrlen)
            print_error(_("Fold backup file %s is too short"), filename);
         fclose(in);
      }

      /* Encode to QR code */
      uint8_t  version = 40;
      uint16_t buf_sz  = qrcode_getBufferSize(version);
      uint8_t *modules = malloc(buf_sz);
      if (!modules) { perror("malloc"); exit(1); }

      QRCode qr;
      if (qrcode_initBytes(&qr, modules, version, ECC_MEDIUM, qrdata, (uint16_t)qrlen) != 0)
         print_error(_("QR encoding failed — data too large"));

      /* Output */
      if (qrcode_path && qrcode_path[0] != '\0') {
         bmp_write(qrcode_path, modules, qr.size);
         printf(_("QR code saved to %s\n"), qrcode_path);
      } else {
         qr_print_terminal(modules, qr.size, init_val->is_color_print);
      }
      free(modules);
      return;
   }

   if (filename == NULL) {
      filename = "windham_backup";
   }

   printf(_("Creating header backup for device %s to %s\n"), device, filename);

   /* ---------- file-exists check ---------- */
#ifdef WINDHAM_PLAT_GNU_LINUX
   if (access(filename, F_OK) != -1) {
      print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);
   }
#else
   FILE *chk = fopen(filename, "r");
   if (chk != NULL) { fclose(chk);
      print_error(_("File %s exists. If you want to overwrite the file, you need to delete the file manually."), filename);
   }
#endif

   if (is_fold) {
      /* ======= FOLD MODE ======= */
      Data     data;
      int64_t  offset;
      load_header_by_device(device, &data, &offset, is_decoy, false);

      uint8_t  master_key[HASHLEN];
      unsigned ret_key_zone, ret_level;
      uint16_t ret_key_location;
      uint8_t  ret_inited_key[HASHLEN];
      size_t   ks_size  = sizeof(Key_slot);
      uint8_t  ks_buf[sizeof(Key_slot)];
      bool     is_mk_bu = (key.key_type == NMOBJ_key_file_type_masterkey);

      if (is_mk_bu) {
         memcpy(master_key, master_key_input, HASHLEN);
         /* Dummy get_master_key call just for consistency; master key is already known */
         get_master_key(data, master_key, key, device,
                        SIZE_MAX, DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                        KEY_SLOT_EXP_MAX, false,
                        &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);
         /* Fill Key_slot with random — indistinguishable from password backup */
         fill_secure_random_bits(ks_buf, ks_size);
         ret_key_zone    = 0;
         ret_key_location = 0;
      } else {
         get_master_key(data, master_key, key, device,
                        SIZE_MAX, DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                        KEY_SLOT_EXP_MAX, false,
                        &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);
         /* Extract the matched Key_slot */
         memcpy(ks_buf, get_slot_loc(data, ret_key_zone, ret_key_location), ks_size);
      }

      /* Build a trimmed EncMetadata (slot 0 only). */
      EncMetadata *meta = &data.metadata;
      uint64_t orig_area = meta->keyslot_location_area;
      uint16_t orig_loc[KEY_SLOT_COUNT];
      uint8_t  orig_lvl[KEY_SLOT_COUNT];
      memcpy(orig_loc, meta->keyslot_location, sizeof(orig_loc));
      memcpy(orig_lvl, meta->keyslot_level,   sizeof(orig_lvl));

      /* Determine which slot index was matched (password path only) */
      unsigned matched = 0;
      if (!is_mk_bu) {
         for (unsigned i = 0; i < KEY_SLOT_COUNT; i++) {
            if (orig_loc[i] == ret_key_location &&
                GET_BIT(orig_area, i) == ret_key_zone) { matched = i; break; }
         }
      }

      /* Keep the matched slot; clear all others */
      uint8_t  saved_key[HASHLEN];
      uint8_t  saved_level;
      uint16_t saved_location;
      if (is_mk_bu) {
         memset(saved_key, 0, HASHLEN);
         saved_level    = 0;
         saved_location = 0;
      } else {
         memcpy(saved_key, meta->keyslot_key[matched], HASHLEN);
         saved_level    = orig_lvl[matched];
         saved_location = orig_loc[matched];
      }

      memset(meta->keyslot_key,      0, sizeof(meta->keyslot_key));
      memset(meta->keyslot_level,    0, sizeof(meta->keyslot_level));
      memset(meta->keyslot_location, 0, sizeof(meta->keyslot_location));
      meta->keyslot_location_area = 0;

      /* Slot 0 now holds the single folded key */
      memcpy(meta->keyslot_key[0], saved_key, HASHLEN);
      meta->keyslot_level[0]    = saved_level;
      meta->keyslot_location[0] = saved_location;
      meta->keyslot_location_area = (uint64_t)(ret_key_zone) << 0;

      /* Write fold backup: Key_slot + uuid_and_salt..metadata */
      FILE *out = fopen(filename, "wb");
      if (!out) print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
      fwrite(ks_buf, 1, ks_size, out);
      fwrite(data.uuid_and_salt, 1,
             (size_t)((uint8_t *)(meta + 1) - data.uuid_and_salt),
             out);
      fclose(out);
      return;
   }

   /* ======= ALL MODE (original behaviour) ======= */
   Data                alldata;
   int64_t             alloffset;
   ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &alldata, &alloffset, is_decoy, false);

#ifdef WINDHAM_PLAT_GNU_LINUX
   int fd = creat(filename, S_IRUSR);
   if (fd == -1)
      print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
   close(fd);
#else
   FILE *allfile = fopen(filename, "wb");
   if (allfile == NULL)
      print_error(_("Cannot create file %s: %s"), filename, strerror(errno));
   fclose(allfile);
#endif

   write_header_to_device(&alldata, filename, 0);
}

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

      uint8_t *mk_mask = backup_meta + 16;

      /* 2. Derive master key and inited_key based on key type */
      uint8_t inited_key[HASHLEN];
      uint8_t master_key[HASHLEN];
      bool is_mk   = (key.key_type == NMOBJ_key_file_type_masterkey);
      bool slot0_empty = true; /* default: assume master-key backup */

      if (is_mk) {
         /* --- master key path --- */
         memcpy(master_key, master_key_input, HASHLEN);
         Data tmp; memset(&tmp, 0, sizeof(tmp));
         memcpy(tmp.uuid_and_salt, backup_meta, meta_len);
         if (!check_master_key_check(tmp, master_key))
            print_error(_("Fold restore: master key check failed"));
         if (!unlock_metadata_using_master_key(&tmp, master_key))
            print_error(_("Fold restore: metadata decrypt failed"));
         /* Check if this is a password backup (keyslot_key[0] non-zero) */
         {
            uint8_t zero[HASHLEN] = {0};
            slot0_empty = (memcmp(tmp.metadata.keyslot_key[0], zero, HASHLEN) == 0);
         }
         if (!slot0_empty) {
            /* Password backup restored with master key: use preserved inited_key */
            memcpy(inited_key, tmp.metadata.keyslot_key[0], HASHLEN);
         } else {
            /* Master-key backup: inited_key is irrelevant; will use random placement */
            memset(inited_key, 0, HASHLEN);
         }
      } else {
         /* --- password path --- */
         prepare_key(key, inited_key, device, false);
         /* master_key derived later via read_key_from_data */
      }

      /* 3. Build Data: fill random, overlay backup fields */
      Data newdata;
      fill_secure_random_bits((uint8_t *)&newdata, sizeof(Data));
      memcpy(newdata.uuid_and_salt, backup_meta, meta_len);

      /* 4. ALWAYS generate random location and zone, regardless of path.
            Same number of random reads prevents side-channel differentiation. */
      uint16_t volatile rnd_loc;
      fill_secure_random_bits((uint8_t *)&rnd_loc, sizeof(rnd_loc));
      uint8_t volatile rnd_zone;
      fill_secure_random_bits(&rnd_zone, 1); rnd_zone %= 2;

      uint16_t keypool_loc;
      uint8_t  zone_idx;

      if (slot0_empty) {
         /* Master-key backup: use random placement */
         keypool_loc = rnd_loc % sizeof(Keypool);
         zone_idx    = rnd_zone;
      } else {
         /* Password backup (or password→master-key restore):
            placement is deterministic from inited_key.  Still incur the
            random calls above so the number of entropy reads is identical. */
         keypool_loc = get_keypool_location_candidate(newdata.master_key_mask, inited_key);
         zone_idx    = rnd_zone;
      }

      /* 5. Place Key_slot in the keypool */
      memcpy(get_slot_loc(newdata, zone_idx, keypool_loc), ks_buf, sizeof(Key_slot));

      /* 6. Derive/verify master key.
            Password restore of a password backup: KDF needed.
            Master-key restore or master-key backup: master key already known. */
      if (!is_mk) {
         /* Password path: derive master key via KDF */
         Data tmp; memcpy(&tmp, &newdata, sizeof(Data));
         unsigned ret_zone, ret_level;
         uint8_t  ret_inited[HASHLEN];
         int result = read_key_from_data(tmp, inited_key, keypool_loc,
                                         DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR,
                                         SIZE_MAX, KEY_SLOT_EXP_MAX, false,
                                         &ret_zone, &ret_level, master_key);
         if (result != NMOBJ_Enclib_calc_okay)
            print_error(_("Fold restore: key derivation failed (error %d)"), result);
      }

      if (!check_master_key_check(newdata, master_key))
         print_error(_("Fold restore: master key check failed"));

      /* 7. Decrypt metadata, set slot 0, re-encrypt */
      if (!unlock_metadata_using_master_key(&newdata, master_key))
         print_error(_("Fold restore: metadata decrypt failed"));

      memset(newdata.metadata.keyslot_key[0], 0, HASHLEN);
      if (!slot0_empty)
         memcpy(newdata.metadata.keyslot_key[0], inited_key, HASHLEN);
      newdata.metadata.keyslot_level[0]    = 0;
      newdata.metadata.keyslot_location[0] = keypool_loc;
      newdata.metadata.keyslot_location_area = (uint64_t)zone_idx << 0;
      for (unsigned i = 1; i < KEY_SLOT_COUNT; i++) {
         memset(newdata.metadata.keyslot_key[i], 0, HASHLEN);
         newdata.metadata.keyslot_level[i]    = 0;
         newdata.metadata.keyslot_location[i] = 0;
      }

      lock_metadata_using_master_key(&newdata, master_key);

      /* 8. Write to device */
      ask_for_conformation(_("Restoring fold backup to device \"%s\". Continue?"), device);
      write_header_to_device(&newdata, device, 0);
      printf(_("Fold restore complete.\n"));
      free(backup_meta);
      return;
   }

   /* ======= ALL MODE (original behaviour) ======= */
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
#elif defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)
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
