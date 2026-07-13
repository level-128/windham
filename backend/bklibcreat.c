#pragma once

#include "bklibkey.c"
#include "bksrclib.c"
#include "../libsrc/auxlib.c"
#include "../include/windham_const.h"

#include "../libplat/chk_enc_supp_stat.c"
#include "../libplat/get_entropy.c"
#include "../libplat/loopctl.c"
#include "../libsrc/ff_exfat.c"



void action_create(
   const
   char *         device,
   const char *   enc_type,
   const Key      key,
   const size_t   target_memory,
   double         target_time,
   const int      target_level,
   const size_t   block_size,
   const uint64_t decoy_size,
   const uint64_t aux_sector_size,
   const bool     is_no_detect_entropy,
   const bool     is_anonymous_key,
   const bool     is_allow_nolock,
   const bool     create_exfat) {
   if (STR_device->is_block == true) {
      CHECK_DEVICE_TOPOLOGY(
         device,
         "",
         parent,
         CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
            mount_points_len, > 0, mount_points,
            (_("Cannot create device %s, device has been mounted at %s. Unmount the device to continue"), device, mount_points[0])
           ,
            (_("Cannot create device %s, unmount the device to continue. Active mount points:"), device));

         int nparts = 0;
         if (is_blkid_available) {
            blkid_probe pr = p_blkid_new_probe_from_filename(device); p_blkid_do_probe(pr);
            const blkid_partlist ls = p_blkid_probe_get_partitions(pr); if (ls != NULL) {
            // partition table present
            nparts = p_blkid_partlist_numof_partitions(ls);
            } p_blkid_free_probe(pr);
         }
         CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(child_ret_len, > 0 && nparts != 0, child,
            (_("Cannot create device: device %s contains partition table and already been mapped as \"%s\". "
                  "Use \"sudo umount %s\" to unmount, then use \"sudo partx %s -d\" to close it."),
               device, child[0], device, device),
            (_("Cannot create device: device %s contains partition table and already been mapped. unmount "
               "all partitions using \"umount\" command and use \"sudo partx %s -d\" to close them. mapped locations:"),
               device, device));

         CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
            child_ret_len, > 0 && nparts == 0, child,
            (_("Cannot create device: device %s has already been mapped as \"%s\" either by Windham or other device mapper "
                  "schemes. Use \"windham Close *name*\" to close it."),
               device, child[0]),
            (_("Cannot create device: device %s has already been mapped by either by Windham or other device mapper schemes. Use "
                  "\"windham Close *name*\" to close them. mapped locations:"),
               device)););
      CHECK_DEVICE_TOPOLOGY_FREE(child);
   }

   enc_type = enc_type
                 ? enc_type
                 : DEFAULT_DISK_ENC_MODE;
   action_new_check_crypt_support_status(enc_type);

   Data      data;
   uint8_t * aux_zone = NULL;
   uint8_t   master_key[HASHLEN];
   uint64_t   start_sector, end_sector;
   int       ret_target_level;

   fill_secure_random_bits(master_key, HASHLEN);

   const int64_t device_block_cnt = STR_device->block_count;
   const int64_t offset           =
      get_new_header_range_and_offset_based_on_size(
         device,
         device_block_cnt,
         &start_sector,
         &end_sector,
         block_size,
         decoy_size,
         aux_sector_size);

   initialize_new_header(&data, master_key, enc_type, start_sector, end_sector, block_size, aux_sector_size);
   if (aux_sector_size != 0) {
      aux_zone = malloc(aux_sector_size * 512);
      init_aux_zone(aux_zone, aux_sector_size * 512);
   }

   add_key_to_keyslot(
      &data,
      master_key,
      key,
      device,
      target_memory,
      target_time,
      target_level,
      is_no_detect_entropy,
      true,
      is_anonymous_key,
      is_allow_nolock,
      &ret_target_level);

   ask_for_conformation(_("Creating encrypt partition on device: %s, All content will be lost. Continue?"), device);

#if !defined(WINDHAM_NO_SHEBANG_ENTRY) && !defined(WINDHAM_ISOC)
   if (STR_device->is_block == false && is_skip_conformation == false) {
      int res = ask_option(_("It seems that you are creating Windham on a file, not device. Do you want to add shebang line "
                   "thus making the file itself as a self-decrypt executable?"),
                   _("No"),
                   _("Yes, and make it identifiable."),
                   NULL);
      if (res == 2) {
         memcpy(data.head, shebang_line, sizeof(shebang_line));
         chmod(device, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
      }
   }
#endif


   // fill random data to first 128K.
#ifndef WINDHAM_ISOC
   #include <fcntl.h>

   if (decoy_size == 0) {
      const int fp = open(device, O_DSYNC | O_WRONLY);
      if (fp < 0) {
         print_error(_("Failed to open %s: %s"), device, strerror(errno));
      }
      for (int i = 0; i < 32; i ++) {
         uint8_t random_buffer[4096];
         fill_secure_random_bits(random_buffer, 4096);
         const ssize_t result = write(fp, random_buffer, sizeof(random_buffer));
         if (result != sizeof(random_buffer)) {
            break;
         }
      }
      close(fp);
   }
#endif

    encrypt_aux_zone_using_master_key(&data, aux_zone, aux_sector_size * 512, master_key);
    write_aux_zone_to_device(device, &data, aux_zone, aux_sector_size * 512);

    /* Save disk_key_mask before OPERATION_LOCK_AND_WRITE encrypts metadata */
    uint8_t saved_disk_key_mask[HASHLEN];
    memcpy(saved_disk_key_mask, data.metadata.disk_key_mask, HASHLEN);
    uint8_t saved_uuid_and_salt[16];
    memcpy(saved_uuid_and_salt, data.uuid_and_salt, 16);

    OPERATION_LOCK_AND_WRITE

    if (create_exfat) {
       uint8_t disk_key[DEFAULT_DISK_KEY_SIZE_BYTES];
       get_metadata_key_or_disk_key_from_master_key(
          master_key, saved_disk_key_mask, saved_uuid_and_salt,
          disk_key, DEFAULT_DISK_KEY_SIZE_BYTES);
      char hex_key[DEFAULT_DISK_KEY_SIZE_BYTES * 2 + 1];
       convert_disk_key_to_hex_format(disk_key, DEFAULT_DISK_KEY_SIZE_BYTES, hex_key);
       ff_exfat_create(device, hex_key, block_size, start_sector, end_sector);
   }

   free(aux_zone);
}
