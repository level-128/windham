#pragma once

#include "../library_intrnlsrc/mapper.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "windham_const.h"

#define MAX_LINE_LENGTH 1024
#define TARGET_PREFIX "name         : "


char ** get_crypto_list() {
   int     crypto_count = 0;
   char    line[MAX_LINE_LENGTH];
   char ** crypto_list = NULL;

   FILE * file = fopen("/proc/crypto", "r");
   if (file == NULL) {
      print_warning(
         _(
            "Cannot determine available encryption mode on the system. Please ensure that the kernel encryption subsystem is available."
         ));
      return NULL;
   }

   while (fgets(line, sizeof(line), file)) {
      if (strncmp(line, TARGET_PREFIX, strlen(TARGET_PREFIX)) == 0) {
         const char * name = line + strlen(TARGET_PREFIX);
         if (*name != '_' && strcmp("stdrng\n", name) != 0) {
            (crypto_count) ++;
            // ReSharper disable once CppDFAMemoryLeak
            crypto_list = realloc(crypto_list, sizeof(char *) * crypto_count);

            crypto_list[crypto_count - 1] = strdup(name);

            char * end = crypto_list[crypto_count - 1] + strlen(crypto_list[crypto_count - 1]) - 1;
            if (*end == '\n') {
               *end = '\0';
            }
         }
      }
   }
   crypto_list               = realloc(crypto_list, sizeof(char *) * (crypto_count + 1));
   crypto_list[crypto_count] = NULL;
   fclose(file);
   // ReSharper disable once CppDFAMemoryLeak
   return crypto_list;
}


void check_encryption_mode_arg(const char * str, int64_t idx[3]) {
#ifndef WINDHAM_USE_NULL_MALLOC
   int dash_count = 0;
   for (int i = 0; str[i] != '\0'; i ++) {
      if (str[i] == '-') {
         dash_count ++;
      }
   }
   if (dash_count != 2) {
      print_error(_("Invalid argument. The encryption scheme should obey the format: \"*cipher*-*chainmode*-*ivmode*\""));
   }
   char * strcpy = strdup(str);

   char * token = strtok(strcpy, "-");
   idx[0]       = is_in_list(token, crypt_list);
   if (idx[0] == -1) {
      print_error(_("Invalid argument. Unrecognized cipher \"%s\". "), token);
   }

   token  = strtok(NULL, "-");
   idx[1] = is_in_list(token, chainmode_list);
   if (idx[1] == -1) {
      print_error(_("Invalid argument. Unrecognized chainmode \"%s\". "), token);
   }

   token  = strtok(NULL, "-");
   idx[2] = is_in_list(token, iv_list);
   if (idx[2] == -1) {
      print_error(_("Invalid argument. Unrecognized ivmode \"%s\". "), token);
   }
   free(strcpy);
#endif
}


void action_new_check_crypt_support_status(const char * str) {
#ifndef WINDHAM_USE_NULL_MALLOC
   int64_t idx[3];
   check_encryption_mode_arg(str, idx);
   char ** crypto_list = get_crypto_list();

   if (crypto_list == NULL) {
      return;
   }

   char chainmode_name[32];
   sprintf(chainmode_name, "%s(%s)", chainmode_list[idx[1]], crypt_list[idx[0]]);
   if (is_in_list(chainmode_name, crypto_list) == -1) {
      ask_for_conformation(
         _(
            "The cipher %s you've requested might not be supported by your current system. Although you can create a "
            "header that employs this encryption scheme, "
            "your system might not be capable of unlocking it. This means you won't be able to access the encrypted "
            "device you've just created with this specific "
            "method on this system. You would need to locate a compatible system, recompile your kernel, or find the "
            "appropriate kernel module to access the "
            "device. Do you wish to proceed?"),
         chainmode_name);
   }

   for (int i = 0; crypto_list[i]; i ++) {
      free(crypto_list[i]);
   }
   free(crypto_list);
#endif
}


void action_create(
   const char *   device,
   const char *   enc_type,
   const Key      key,
   const size_t   target_memory,
   double   target_time,
   const int      target_level,
   const size_t   block_size,
   const uint64_t decoy_size,
   const bool     is_no_detect_entropy,
   const bool     is_anonymous_key,
   const bool     is_allow_nolock) {
   CHECK_DEVICE_TOPOLOGY(
      device,
      "",
      parent,
      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
         mount_points_len, > 0, mount_points,
         (_("Cannot create device %s, device has been mounted at %s. Unmount the device to continue"), device, mount_points[0]),
         (_("Cannot create device %s, unmount the device to continue. Active mount points:"), device));

      blkid_probe pr = blkid_new_probe_from_filename(device); blkid_do_probe(pr);
      const blkid_partlist ls = blkid_probe_get_partitions(pr); int nparts = 0; if (ls != NULL) {
      // partition table present
      nparts = blkid_partlist_numof_partitions(ls);
      } blkid_free_probe(pr);
      CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(child_ret_len, > 0 && nparts != 0, child,
         (_("Cannot create device: device %s contains partition table and already been mapped as \"%s\"."
               "Use \"sudo partx %s -d\" to close it."),
            device, child[0], device),
         (_("Cannot create device: device %s contains partition table and already been mapped. Use "
               "\"sudo partx %s -d\" to close them. mapped locations:"),
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

   enc_type = enc_type
                 ? enc_type
                 : DEFAULT_DISK_ENC_MODE;
   action_new_check_crypt_support_status(enc_type);

   Data    data;
   uint8_t master_key[HASHLEN];
   size_t  start_sector, end_sector;
   int ret_target_level;
     
   fill_secure_random_bits(master_key, HASHLEN);

   const size_t  device_block_cnt = STR_device->block_count;
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

   // fill random data to first 128K.
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

   OPERATION_LOCK_AND_WRITE
};
