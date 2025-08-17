#pragma once

#include "../libsrc/mapper.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "../include/windham_const.h"

#include "../libplat/chk_enc_supp_stat.c"
#include "../libplat/get_entropy.c"



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
   const bool     is_no_detect_entropy,
   const bool     is_anonymous_key,
   const bool     is_allow_nolock) {
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

         blkid_probe pr = blkid_new_probe_from_filename(device); blkid_do_probe(pr);
         const blkid_partlist ls = blkid_probe_get_partitions(pr); int nparts = 0; if (ls != NULL) {
         // partition table present
         nparts = blkid_partlist_numof_partitions(ls);
         } blkid_free_probe(pr);
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

   Data    data;
   uint8_t master_key[HASHLEN];
   size_t  start_sector, end_sector;
   int     ret_target_level;

   fill_secure_random_bits(master_key, HASHLEN);

   const int64_t device_block_cnt = STR_device->block_count;
   const int64_t offset           =
      get_new_header_range_and_offset_based_on_size(
         device,
         device_block_cnt,
         &start_sector,
         &end_sector,
         block_size,
         decoy_size);

   initialize_new_header(&data, master_key, enc_type, start_sector, end_sector, block_size);

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

#ifndef WINDHAM_NO_SHEBANG_ENTRY
   if (STR_device->is_block == false) {
      int res = ask_option(_("It seems that you are creating Windham on a file, not device. Do you want to add shebang line "
                   "thus making the file itself as a self-decrypt executable?"),
                   _("No"),
                   _("Yes, and make it identifiable."),
                   NULL);
      if (res == 2) {
         memcpy(data.head, shebang_line, sizeof(shebang_line));
      }
#endif
   }


   // fill random data to first 128K.
#ifndef WINDHAM_ISOC
   #include <fcntl.h>

   if (decoy_size == 0) {
      const int fp = open(device, O_DSYNC | O_WRONLY);
      if (fp == 0) {
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

   OPERATION_LOCK_AND_WRITE
}
