#pragma once

#include "../libsrc/windhamtab.c"
#include "../libplat/loopctl.c"
#include "bklibkey.c"
#include "bksrclib.c"
#include "bklibaux.c"
#include "../libsrc/probelib.c"
#include "../include/windham_const.h"


/* ───────────────────────────────────────────
 * UUID → device path map
 * ─────────────────────────────────────────── */

typedef struct {
    uint8_t uuid[16];
    char   device_path[FILENAME_MAX + 1];
    bool   is_opened;
    bool   is_failed;
} UuidMapEntry;

static DynBuf       uuid_map;
static bool         uuid_map_built = false;
static const char * aux_link_paths_global = NULL;


static void build_uuid_map(const char *restrict_paths) {
    if (uuid_map_built) return;
    uuid_map_built = true;
    aux_link_paths_global = restrict_paths;
    db_init(&uuid_map, sizeof(UuidMapEntry));

    // If paths are provided, probe only those paths
    if (restrict_paths != NULL && restrict_paths[0] != '\0') {
        const char *p = restrict_paths;
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if (*p == '\0') break;

            const char *start = p;
            while (*p != '\0' && *p != ',' && *p != ' ') p++;
            size_t len = (size_t)(p - start);
            if (len == 0) continue;
            if (len > FILENAME_MAX) len = FILENAME_MAX;

            char token[FILENAME_MAX + 1];
            memcpy(token, start, len);
            token[len] = '\0';

            uint8_t probe_uuid[16];
            int     probe_type;
            if (probe_single_device(token, probe_uuid, &probe_type)) {
                if (memcmp(probe_uuid, (uint8_t[16]){0}, 16) != 0) {
                    UuidMapEntry e = { .is_opened = false, .is_failed = false };
                    memcpy(e.uuid, probe_uuid, 16);
                    strncpy(e.device_path, token, FILENAME_MAX);
                    e.device_path[FILENAME_MAX] = '\0';
                    db_add(&uuid_map, &e);
                }
            }
        }
        return;
    }

    // Default: scan /proc/partitions
    FILE *pp = fopen("/proc/partitions", "r");
    if (!pp) {
        print_warning(_("Cannot open /proc/partitions — linked partition resolution disabled."));
        return;
    }

    char line[256];
    fgets(line, sizeof(line), pp);
    fgets(line, sizeof(line), pp);

    while (fgets(line, sizeof(line), pp)) {
        unsigned      major_num = 0, minor_num = 0;
        unsigned long blocks    = 0;
        char          name[128] = {0};

        if (sscanf(line, "%u %u %lu %127s", &major_num, &minor_num, &blocks, name) != 4) continue;
        if (major_num == 0 || name[0] == '\0') continue;

        char    dev_path[256];
        snprintf(dev_path, sizeof(dev_path), "/dev/%s", name);

        uint8_t probe_uuid[16];
        int     probe_type;
        if (probe_single_device(dev_path, probe_uuid, &probe_type)) {
            if (memcmp(probe_uuid, (uint8_t[16]){0}, 16) != 0) {
                UuidMapEntry e = { .is_opened = false, .is_failed = false };
                memcpy(e.uuid, probe_uuid, 16);
                strncpy(e.device_path, dev_path, FILENAME_MAX);
                e.device_path[FILENAME_MAX] = '\0';
                db_add(&uuid_map, &e);
            }
        }
    }
    fclose(pp);
}


static int find_uuid_in_map(const uint8_t uuid[16]) {
    for (size_t i = 0; i < db_count(&uuid_map); i++) {
        if (memcmp(((UuidMapEntry *)db_get(&uuid_map, i))->uuid, uuid, 16) == 0) return (int)i;
    }
    return -1;
}

static DynBuf seen_uuids;

static bool uuid_is_seen(const uint8_t uuid[16]) {
    if (seen_uuids.elem_size == 0) db_init(&seen_uuids, 16);
    for (size_t i = 0; i < db_count(&seen_uuids); i++) {
        if (memcmp((uint8_t *)db_get(&seen_uuids, i), uuid, 16) == 0) return true;
    }
    return false;
}

static void uuid_mark_seen(const uint8_t uuid[16]) {
    if (!uuid_is_seen(uuid)) {
        db_add(&seen_uuids, uuid);
    }
}

static void uuid_map_mark_opened(const uint8_t uuid[16]) {
    uuid_mark_seen(uuid);
    int idx = find_uuid_in_map(uuid);
    if (idx >= 0) ((UuidMapEntry *)db_get(&uuid_map, (size_t)idx))->is_opened = true;
}

static void uuid_map_mark_failed(const uint8_t uuid[16]) {
    int idx = find_uuid_in_map(uuid);
    if (idx >= 0) ((UuidMapEntry *)db_get(&uuid_map, (size_t)idx))->is_failed = true;
}

static bool uuid_map_is_processed(const uint8_t uuid[16]) {
    int idx = find_uuid_in_map(uuid);
    if (idx < 0) return false;
    UuidMapEntry *e = db_get(&uuid_map, (size_t)idx);
    return e->is_opened || e->is_failed;
}

static const char *uuid_map_get_path(const uint8_t uuid[16]) {
    if (!uuid_map_built) build_uuid_map(aux_link_paths_global);
    int idx = find_uuid_in_map(uuid);
    return (idx >= 0) ? ((UuidMapEntry *)db_get(&uuid_map, (size_t)idx))->device_path : NULL;
}


/* ───────────────────────────────────────────
 * FIFO (deque at front)
 * ─────────────────────────────────────────── */

#define FIFO_MAX 256

typedef struct {
    char    device_path[FILENAME_MAX + 1];
    int     index;
    bool    has_stop_flag;

    Key     key;
    uint8_t master_key[HASHLEN];

    bool     is_link_open;
    char32_t *link_key;
    uint16_t link_key_len;
    int8_t   link_unlock_level;

    const char *target_name;   // non-NULL only for initial device

    uint64_t max_unlock_mem;
    double   max_unlock_time;
    int      max_unlock_level;
    bool     is_allow_nolock;
    bool     is_decoy;

    bool is_readonly, is_allow_discards, is_no_read_wq, is_no_write_wq, is_no_map_partition;
    bool is_nokeyring, is_no_aux;
    bool is_dry_run;
    unsigned timeout;
} FifoEntry;

#define FIFO_DEF_CAPACITY 16
static FifoEntry *fifo_data;
static size_t     fifo_count;
static size_t     fifo_capacity;

static void fifo_push_front(FifoEntry e) {
    if (fifo_count >= fifo_capacity) {
        fifo_capacity = fifo_capacity ? fifo_capacity * 2 : FIFO_DEF_CAPACITY;
        fifo_data = realloc(fifo_data, fifo_capacity * sizeof(FifoEntry));
        if (!fifo_data) print_error(_("Out of memory"));
    }
    memmove(&fifo_data[1], &fifo_data[0], fifo_count * sizeof(FifoEntry));
    fifo_data[0] = e;
    fifo_count++;
}


static FifoEntry fifo_pop_front(void) {
    FifoEntry e = fifo_data[0];
    fifo_count--;
    memmove(&fifo_data[0], &fifo_data[1], fifo_count * sizeof(FifoEntry));
    return e;
}

static bool fifo_is_empty(void) {
    return fifo_count == 0;
}


/* ───────────────────────────────────────────
 * LINK_OPEN collected entries
 * ─────────────────────────────────────────── */

typedef struct {
    char32_t *target_key;
    uint16_t target_key_len;
    uint8_t  target_uuid[16];
    int8_t   target_unlock_level;
    uint8_t  flags;
    uint8_t  prio;
} LinkOpenEntry;

#define MAX_LINK_OPEN 256

typedef struct {
    DynBuf entries;
} LinkOpenList;


static int link_open_prio_cmp_desc(const void *a, const void *b) {
    const LinkOpenEntry *ea = (const LinkOpenEntry *) a;
    const LinkOpenEntry *eb = (const LinkOpenEntry *) b;
    if (ea->prio > eb->prio) return -1;
    if (ea->prio < eb->prio) return 1;
    return 0;
}


/* ───────────────────────────────────────────
 * check_sector_size_for_resize
 * ─────────────────────────────────────────── */

void check_sector_size_for_resize(const char * device, Data * data_, uint8_t master_key[HASHLEN], bool is_suspend) {
   if (STR_device->block_count < 0) {
      return;
   }
   size_t block_count = STR_device->block_count / (data_->metadata.block_size / 512) * (data_->metadata.block_size / 512);
   if (block_count != data_->metadata.end_sector) {
      if (is_suspend) {
         print_error(_("The device's last sector (%zu) does not match with the underlying device's size (%zu). Cannot resize "
                       "the suspend partition since windham partition is designed to be tamper resistance. Resume the partition "
                       "and re-open it to resize."), data_->metadata.end_sector, STR_device->block_count);
      }

#define OPTION_MSG _("The device's last sector (%zu) does not match with the underlying device's size (%zu). Do you want to"\
      "adjust the sector range?")
      char q_str[sizeof(OPTION_MSG) + 2 * sizeof(STRINGIFY(INT64_MAX))];
      sprintf(
         q_str,
         OPTION_MSG,
         data_->metadata.end_sector,
         STR_device->block_count);
#undef OPTION_MSG

      switch (ask_option(
         q_str,
         _("Yes."),
         block_count < data_->metadata.end_sector
            ? _("No, and abort the operation since the last sector is out of range.")
            : _("No."),
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


/* ───────────────────────────────────────────
 * action_open_single — opens ONE device
 * Returns: true if successfully opened & mapped
 *          (dry-run always returns true)
 * out_links: LINK_OPEN entries found (caller frees keys)
 * out_uuid:  UUID of the opened device
 * ─────────────────────────────────────────── */

static bool action_open_single(
   FifoEntry *   entry,
   LinkOpenList *out_links,
   uint8_t       out_uuid[16])
{
    Data    data;
    int64_t offset;
    uint8_t *disk_key = NULL;
    size_t   dk_size = 0;

   db_init(&out_links->entries, sizeof(LinkOpenEntry));
   memset(out_uuid, 0, 16);

   uint8_t  master_key[HASHLEN];
   unsigned ret_key_zone, ret_level;
   uint16_t ret_key_location;
   uint8_t  ret_inited_key[HASHLEN];

    ENUM_MAPPER_DEVSTAT header_type = load_header_by_device(entry->device_path, &data, &offset, entry->is_decoy);

    if (uuid_is_seen(data.uuid_and_salt) && !entry->is_dry_run) {
       return false;
    }

    assert(!entry->is_link_open || header_type != NMOBJ_MAPPER_DEVSTAT_DECOY && "decoy partition should not be "
       "linked and be detected!");

   memcpy(out_uuid, data.uuid_and_salt, 16);

   char random_target_name[] = "windham-123e4567-e89b-12d3-a456-abcdef123456";
   const char *effective_target_name;
   if (entry->target_name != NULL) {
      effective_target_name = entry->target_name;
   } else {
      generate_UUID_from_bytes(data.uuid_and_salt, random_target_name + strlen("windham-"));
      effective_target_name = random_target_name;
   }


   switch (header_type) {

   case NMOBJ_MAPPER_DEVSTAT_SUSP: 
      if (entry->is_link_open) {
         print_warning(_("Linked device %s is suspended. Cannot cascade further links from a suspended device."),
                        entry->device_path);
         return false;
      }
      convert_metadata_endianness_to_h(&data.metadata);

      dk_size = (size_t)data.metadata.disk_key_size_in_bits_div_64 * 64 / 8;
      disk_key = calloc(1, dk_size);
      if (!disk_key) {
         perror("malloc");
         exit(1);
      }
         check_sector_size_for_resize(entry->device_path, &data, NULL, true);

         if (! entry->is_dry_run) {
            uint8_t zeros[HASHLEN] = {0};
            get_metadata_key_or_disk_key_from_master_key(data.metadata.disk_key_mask, zeros, data.uuid_and_salt, disk_key, dk_size);
            create_crypt_mapping_from_disk_key(
               entry->device_path, effective_target_name, data.metadata.enc_type, disk_key, dk_size,
            data.uuid_and_salt, data.metadata.start_sector, data.metadata.end_sector,
            data.metadata.block_size,
            entry->is_readonly, entry->is_allow_discards,
            entry->is_no_read_wq, entry->is_no_write_wq,
            entry->is_no_map_partition);
         if (!entry->is_link_open) {
            print_warning(_("Device %s is unlocked and suspended. Don't forget to close it using \"Resume\" when appropriate."),
                           entry->device_path);
         }
      }
      free(disk_key);
      return true;
   
   case NMOBJ_MAPPER_DEVSTAT_NORM:
   // kernel key retension service
      if (mapper_keyring_get_disk_serial(data.uuid_and_salt, disk_key) == true) {
         if (!entry->is_link_open) printf(_("Found kernel keyring key\n"));
         size_t start_sector, end_sector;
         get_new_header_range_and_offset_based_on_size(
            entry->device_path, STR_device->block_count,
            &start_sector, &end_sector, DEFAULT_BLOCK_SIZE, 0,
            DEFAULT_AUX_SECTOR_SIZE * 512);
          create_crypt_mapping_from_disk_key(
             entry->device_path, effective_target_name, DEFAULT_DISK_ENC_MODE, disk_key, DEFAULT_DISK_KEY_SIZE_BYTES,
            data.uuid_and_salt, start_sector, end_sector, DEFAULT_BLOCK_SIZE,
            entry->is_readonly, entry->is_allow_discards,
            entry->is_no_read_wq, entry->is_no_write_wq,
            entry->is_no_map_partition);
         free(disk_key);
         return true;
      }
   // falls through

   case NMOBJ_MAPPER_DEVSTAT_DECOY: {
      if (entry->is_dry_run) {
         if (!entry->is_link_open) {
            printf(_("Unlocking %s\n"), entry->device_path);
         }
      } else {
         printf(_("Unlocking %s%s as %s...\n"),
                entry->is_link_open ? _("linked device ") : "",
                entry->device_path, effective_target_name);
      }

      if (entry->is_link_open) {
         // Use get_master_key with pre-hashed char32_t password
         Key link_key = {
            .key_or_keyfile_location = (char *)entry->link_key,
            .key_type                = NMOBJ_key_file_type_key_char32_t_str,
            .key_data_len            = entry->link_key_len,
         };
         uint8_t link_master_key[HASHLEN] = {0};
         get_master_key(
            data, link_master_key, link_key, entry->device_path,
            entry->max_unlock_mem, entry->max_unlock_time,
            entry->link_unlock_level,
            entry->is_allow_nolock,
            &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);
         memcpy(master_key, link_master_key, HASHLEN);

         if (!unlock_metadata_using_master_key(&data, master_key)) {
            print_warning(_("Linked device %s header may be damaged."), entry->device_path);
            return false;
         }

         if (! entry->is_decoy) {
            check_sector_size_for_resize(entry->device_path, &data, master_key, false);
         }
      } else {
         // Normal unlock path (interactive or command-line key)
         get_master_key(
            data, entry->master_key, entry->key, entry->device_path,
            entry->max_unlock_mem, entry->max_unlock_time, entry->max_unlock_level,
            entry->is_allow_nolock,
            &ret_level, &ret_key_zone, &ret_key_location, ret_inited_key);

         memcpy(master_key, entry->master_key, HASHLEN);

         if (!unlock_metadata_using_master_key(&data, master_key)) {
            print_error(_("The header is likely damaged, which means you can't unlock your device even using your masterkey. Sorry, there is nothing that I could do..."));
         }

         if (! entry->is_decoy) {
            check_sector_size_for_resize(entry->device_path, &data, master_key, false);
         }
      }
      // Metadata is now decrypted — compute actual disk key size
      dk_size = (size_t)data.metadata.disk_key_size_in_bits_div_64 * 64 / 8;
      disk_key = calloc(1, dk_size);
      if (!disk_key) { 
         perror("malloc");
         exit(1);
      }


      // Probe aux zone
      if (!entry->is_no_aux && !entry->is_dry_run) {
         size_t  aux_zone_size = 0;
         uint8_t *aux_zone = read_aux_zone_from_device(entry->device_path, &data, &aux_zone_size);

         if (aux_zone_size != 0) {
            if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
               print_warning(_("Failed to decrypt aux zone. The header may be damaged."));
            } else {
               const uint8_t *aux_slot_key = ret_inited_key;
                int            aux_count    = 0;
                uint32_t       pointer      = 0;

               while (true) {
                  bool     is_public   = false;
                  uint32_t slot_offset = 0;
                  AuxSlot *slot = probe_aux_from_aux_zone(aux_zone, aux_zone_size, &pointer,
                                                          aux_slot_key, &is_public, &slot_offset);
                  if (slot == NULL) break;
                  aux_count++;

                  uint8_t aux_type = ((uint8_t *)slot->content_char32_be)[0];

                  if (aux_type == NMOBJ_AUX_TYPE_LINK_OPEN) {
                     uint8_t  link_uuid[16];
                     int8_t   link_unlock_level;
                     uint8_t  link_prio, link_flags;
                     char32_t *target_key = NULL;
                     uint16_t target_key_len = 0;

                     if (get_aux_link_open_data(slot, link_uuid,
                                                &link_unlock_level, &link_prio, &link_flags,
                                                &target_key, &target_key_len)) {
                        LinkOpenEntry le_copy;
                        le_copy.target_key         = target_key;
                        le_copy.target_key_len     = target_key_len;
                        memcpy(le_copy.target_uuid, link_uuid, 16);
                        le_copy.target_unlock_level = link_unlock_level;
                        le_copy.flags              = link_flags;
                        le_copy.prio               = link_prio;
                        db_add(&out_links->entries, &le_copy);
                     }
                  } else {
                     print_aux_entry(slot, slot_offset, is_public, aux_count);
                  }
                  free(slot);
               }

               if (!entry->is_link_open) {
                  if (aux_count == 0) {
                     printf(_("No aux entries found.\n"));
                  } else {
                     printf(_("Found %d aux entry(ies).\n"), aux_count);
                  }
               }
            }
         } else {
            if (!entry->is_link_open) {
               printf(_("No aux zone on this device.\n"));
            }
         }
         free(aux_zone);
      }

      if (! entry->is_dry_run) {
          get_metadata_key_or_disk_key_from_master_key(master_key, data.metadata.disk_key_mask, data.uuid_and_salt, disk_key, dk_size);
         if (entry->timeout && !entry->is_decoy) {
            mapper_keyring_add_disk_key(disk_key, data.uuid_and_salt, data.metadata, entry->timeout);
         }
          create_crypt_mapping_from_disk_key(
             entry->device_path, effective_target_name, data.metadata.enc_type, disk_key, dk_size,
             data.uuid_and_salt, data.metadata.start_sector, data.metadata.end_sector,
            data.metadata.block_size,
            entry->is_readonly, entry->is_allow_discards,
            entry->is_no_read_wq, entry->is_no_write_wq,
            entry->is_no_map_partition);
      } else {
         char uuid_str[37];
         generate_UUID_from_bytes(data.uuid_and_salt, uuid_str);
         printf(_("dry run complete, opened with master key:\n"));
         print_hex_array(HASHLEN, master_key);

         printf(
            _("\nAdditional device parameters: \n"
               "UUID: %s\nSize (MiB): %"PRIu64"\nCrypto algorithm: %s\nKey Length: %zu"
               "Start sector %"PRIu64"\nEnd sector %"PRIu64"\nBlock size %hu\n"),
            uuid_str,
            (data.metadata.end_sector - data.metadata.start_sector) / 2 / 1024,
            data.metadata.enc_type,
            dk_size,
            data.metadata.start_sector,
            data.metadata.end_sector,
            data.metadata.block_size);

         printf(_("\nkey slot status:\n"));
         bool is_no_key = true;
         for (int i = 0; i < KEY_SLOT_COUNT; i++) {
            if (data.metadata.keyslot_level[i] != 0) {
               is_no_key = false;
               if (memcmp(data.metadata.keyslot_key[i], (uint8_t[HASHLEN]){0}, HASHLEN) == 0) {
                  printf(_("Slot %i used by anonymous key.\n"), i);
               } else {
                  printf(_("Slot %i used; identifier: "), i);
                  print_hex_array(HASHLEN / 4, data.metadata.keyslot_key[i]);
               }
            }
         }
         if (is_no_key){
            printf(_("All slots are EMPTY! this device is accessible only by master key.\n"));
         }
         
      }
      free(disk_key);
      return true;
   }
   }
   free(disk_key);
   return false;
}


/* ───────────────────────────────────────────
 * action_open — FIFO loop with LINK_OPEN cascade
 * ─────────────────────────────────────────── */

void action_open(
   const char * device,
   const char * target_name,
   unsigned     timeout,
   PARAMS_FOR_KEY,
   bool is_dry_run,
   bool is_target_readonly,
   bool is_allow_discards,
   bool is_no_read_workqueue,
   bool is_no_write_workqueue,
   bool is_no_map_partition,
   bool is_nokeyring,
   bool is_no_aux) {

   if (STR_device->is_block == true) {
      CHECK_DEVICE_TOPOLOGY(
         device, "",
         parent,
         CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(
            mount_points_len, > 0, mount_points,
            (_("Cannot open device %s: device has been mounted at %s. Unmount the device to continue"),
               device, mount_points[0]),
            (_("Cannot open device %s: unmount the device to continue. Active mount points:"),
               device));
         blkid_probe pr = blkid_new_probe_from_filename(device); blkid_do_probe(pr);
         const blkid_partlist ls = blkid_probe_get_partitions(pr); int nparts = 0;
         if (ls != NULL) {
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
   }

   if (is_nokeyring) {
      is_kernel_keyring_exist = false;
   } else {
      kernel_keyring_init();
   }

   // Push initial device to FIFO
   FifoEntry init_entry = {0};
   strncpy(init_entry.device_path, device, FILENAME_MAX);
   init_entry.index          = 0;
   init_entry.has_stop_flag  = false;
   init_entry.key            = key;
   memcpy(init_entry.master_key, master_key, HASHLEN);
   init_entry.is_link_open       = false;
   init_entry.target_name        = target_name;
   init_entry.max_unlock_mem     = max_unlock_mem;
   init_entry.max_unlock_time    = max_unlock_time;
   init_entry.max_unlock_level   = max_unlock_level;
   init_entry.is_allow_nolock    = is_allow_nolock;
   init_entry.is_decoy           = is_decoy;
   init_entry.is_readonly        = is_target_readonly;
   init_entry.is_allow_discards  = is_allow_discards;
   init_entry.is_no_read_wq      = is_no_read_workqueue;
   init_entry.is_no_write_wq     = is_no_write_workqueue;
   init_entry.is_no_map_partition = is_no_map_partition;
   init_entry.is_nokeyring       = is_nokeyring;
   init_entry.is_no_aux          = is_no_aux;
   init_entry.is_dry_run         = is_dry_run;
   init_entry.timeout            = timeout;
   fifo_push_front(init_entry);

   // Main cascade loop
   while (!fifo_is_empty()) {
      FifoEntry entry = fifo_pop_front();

      LinkOpenList links;
      uint8_t      device_uuid[16];
      bool success = action_open_single(&entry, &links, device_uuid);

      if (success) {
         uuid_map_mark_opened(device_uuid);
      } else {
         uuid_map_mark_failed(device_uuid);
      }

      // STOP_EXEC: on success, discard remaining siblings at this index
      if (success && entry.has_stop_flag) {
         int skipped = 0;
          while (fifo_count > 0 && fifo_data[0].index == entry.index) {
             skipped++;
             fifo_count--;
             memmove(&fifo_data[0], &fifo_data[1], fifo_count * sizeof(FifoEntry));
         }
         if (skipped > 0) {
            printf(_("SHORTCUT: linked device %s opened, skipping %d remaining sibling(s)\n"),
                   entry.device_path, skipped);
         }
      }

      // Sort by prio DESC, then push in order so lowest prio ends up at FIFO front
      qsort(links.entries.data, db_count(&links.entries), sizeof(LinkOpenEntry), link_open_prio_cmp_desc);

      for (size_t li = 0; li < db_count(&links.entries); li++) {
         LinkOpenEntry *le = db_get(&links.entries, li);

         const char *link_path = uuid_map_get_path(le->target_uuid);
         if (link_path == NULL) {
            print_warning(_("Cannot resolve UUID for linked partition."));
            free(le->target_key);
            continue;
         }

         FifoEntry child = {0};
         strncpy(child.device_path, link_path, FILENAME_MAX);
         child.index             = entry.index + 1;
         child.has_stop_flag     = (le->flags & AUX_CONTENT_LINK_OPEN_FLG_STOP_EXEC_NEXT_IF_SUCC) != 0;
         child.is_link_open      = true;
         child.link_key          = le->target_key;
         child.link_key_len      = le->target_key_len;
         child.link_unlock_level = le->target_unlock_level;
         child.max_unlock_mem     = entry.max_unlock_mem;
         child.max_unlock_time    = entry.max_unlock_time;
         child.max_unlock_level   = entry.max_unlock_level;
         child.is_allow_nolock    = entry.is_allow_nolock;
         child.is_decoy           = false; // no decoy is allowed during LINK_OPEN cascade
         child.is_readonly        = entry.is_readonly;
         child.is_allow_discards  = entry.is_allow_discards;
         child.is_no_read_wq      = entry.is_no_read_wq;
         child.is_no_write_wq     = entry.is_no_write_wq;
         child.is_no_map_partition = entry.is_no_map_partition;
         child.is_nokeyring       = true; 
         child.is_no_aux          = entry.is_no_aux;
         child.is_dry_run         = entry.is_dry_run;
         child.timeout            = entry.timeout;

         // init_device for the linked device
         init_device(link_path, entry.is_dry_run == false, entry.is_readonly, false, false, 0, 0);
         fifo_push_front(child);
      }
   }
}


/* ───────────────────────────────────────────
 * action_open_ — outer wrapper
 * ─────────────────────────────────────────── */

#ifndef WINDHAM_ISOC
static void _action_open_print_summary(int i, WindhamtabEntity entities) {
#define HAS_FLG(x) entities.option_flags & (1 << x)
   printf("Entity %d, pass %hu:\n", i + 1, entities.pass);
   printf("\tDevice: %s\n", entities.device);
   printf("\tTo: %s\n", entities.to);
   printf("\tKey: %s\n", entities.key);
   printf("\targs:");
   if (HAS_FLG(NMOBJ_windhamtab_ro))     printf(" readonly");
   if (HAS_FLG(NMOBJ_windhamtab_no_read_wq))    printf(" no-read-workqueue");
   if (HAS_FLG(NMOBJ_windhamtab_no_write_wq))   printf(" no-write-workqueue");
   if (HAS_FLG(NMOBJ_windhamtab_target_allow_discards)) printf(" allow-discards");
   if (HAS_FLG(NMOBJ_windhamtab_nofail))       printf(" nofail");
   if (HAS_FLG(NMOBJ_windhamtab_systemd))      printf(" systemd");
   if (HAS_FLG(NMOBJ_windhamtab_is_no_map_partition)) printf(" no-map-partition");
   if (HAS_FLG(NMOBJ_windhamtab_max_unlock_mem))  printf(" max-unlock-mem=%zu", entities.max_unlock_mem);
   if (HAS_FLG(NMOBJ_windhamtab_max_unlock_time)) printf(" max-unlock-time=%f", entities.max_unlock_time);
   printf("\n");
#undef HAS_FLG
}
#endif

void action_open_(
   const char * uninit_device,
   const char * windhamtab_file,
   const char * target_name,
   unsigned     timeout,
   int          selected_windham_pass,
   PARAMS_FOR_KEY,
   bool is_dry_run,
   bool is_target_readonly,
   bool is_allow_discards,
   bool is_no_read_workqueue,
   bool is_no_write_workqueue,
   bool is_no_map_partition,
   bool is_nokeyring,
   bool is_nofail,
   bool is_selected_windhamtab_pass,
   bool is_no_aux,
   const char * aux_link_paths) {

   aux_link_paths_global = aux_link_paths;

   if (strcmp(uninit_device, "TAB") == 0) {
#ifndef WINDHAM_ISOC
      int entity_count;
      if (windhamtab_file == NULL) {
         windhamtab_file = WINDHAMTAB_FILE;
      }
      WindhamtabEntity *entities = parse_file(
         windhamtab_file, &entity_count,
         is_selected_windhamtab_pass, selected_windham_pass);

      if (entity_count == 0) {
         printf(_("No entities in windhamtab file. Nothing to do.\n"));
         return;
      }

      uint8_t key_raw[HASHLEN];

      for (int i = 0; i < entity_count; i++) {
         if (is_pid1) {
            printk("%s: Pass %hu, Device %s, To %s, Flag %u",
                   windhamtab_file, entities[i].pass,
                   entities[i].device, entities[i].to,
                   entities[i].option_flags);
         } else {
            _action_open_print_summary(i, entities[i]);
         }

#define HAS_FLGI(x) entities[i].option_flags & (1 << x)

         init_device(entities[i].device, false, false,
                     HAS_FLGI(NMOBJ_windhamtab_nofail), true, 0, 0);

         Key entity_key = key;
         if (strcmp(entities[i].key, "ASK") == 0) {
            if (key.key_type != NMOBJ_key_file_type_key) {
               entity_key.key_type = HAS_FLGI(NMOBJ_windhamtab_systemd)
                                        ? NMOBJ_key_file_type_input_systemd
                                        : NMOBJ_key_file_type_input_stdin;
               entity_key.key_or_keyfile_location = NULL;
            }
         } else if (starts_with(entities[i].key, "CLEVIS=") == true) {
            char *exec_dir[]     = {"/usr/bin", "/bin", "/sbin", "/usr/sbin", "~/local/bin", NULL};
            char *dup_stdout     = NULL;
            size_t dup_stdout_len = 0;
            int   exec_ret_val   = 0;
            bool  success;

            int key_fd_in = open(entities[i].key + strlen("CLEVIS="), O_RDONLY);
            if (key_fd_in == -1) {
               switch (errno) {
               case ENOENT: print_error(_("Clevis file %s does not exist."), entities[i].key + strlen("CLEVIS="));
               case EACCES: print_error(_("invalid permission to open clevis file. Are you root?"));
               }
            }

            success = exec_name("clevis", exec_dir, key_fd_in,
                                &dup_stdout, &dup_stdout_len, &exec_ret_val,
                                NMOBJ_exec_name_wait_child, "decrypt", NULL);
            if (success == false) {
               if (errno == ENOENT) {
                  print_error(_("clevis not found."));
               } else {
                  print_error(_("cannot invoke clevis: %s"), strerror(errno));
               }
            } else if (exec_ret_val != 0) {
               print_error(_("cannot extract key from clevis: %s"), dup_stdout);
            }
            close(key_fd_in);
            if (master_key_to_byte_array(dup_stdout, (uint8_t *)key_raw) == false) {
               print_error(_("error when parsing clevis: invalid format."));
            }
            entity_key.key_or_keyfile_location = (char *)key_raw;
            entity_key.key_type                = NMOBJ_key_file_type_key_raw;
            free(dup_stdout);
         } else {
            entity_key.key_or_keyfile_location = entities[i].key + strlen("KEYFILE=");
            entity_key.key_type                = NMOBJ_key_file_type_file;
         }

         action_open(
            STR_device->name, entities[i].to, 0,
            entity_key, master_key,
            HAS_FLGI(NMOBJ_windhamtab_max_unlock_mem) ? entities[i].max_unlock_mem : max_unlock_mem,
            HAS_FLGI(NMOBJ_windhamtab_max_unlock_time) ? entities[i].max_unlock_time : max_unlock_time,
            0, false, false,
            is_dry_run,
            HAS_FLGI(NMOBJ_windhamtab_ro) || is_target_readonly,
            HAS_FLGI(NMOBJ_windhamtab_target_allow_discards) || is_allow_discards,
            HAS_FLGI(NMOBJ_windhamtab_no_read_wq) || is_no_read_workqueue,
            HAS_FLGI(NMOBJ_windhamtab_no_write_wq) || is_no_write_workqueue,
            HAS_FLGI(NMOBJ_windhamtab_is_no_map_partition),
            true, is_no_aux);
      }
#undef HAS_FLGI
#else
      print_error(_("ISO C mode does not support windhamtab mode."));
#endif
   } else {
      init_device(uninit_device, is_dry_run == false, is_target_readonly, is_nofail, is_decoy, 0, 0);
      action_open(
         STR_device->name, target_name, timeout,
         key, master_key,
         max_unlock_mem, max_unlock_time, max_unlock_level,
         is_allow_nolock, is_decoy,
         is_dry_run, is_target_readonly, is_allow_discards,
         is_no_read_workqueue, is_no_write_workqueue,
         is_no_map_partition, is_nokeyring, is_no_aux);
   }
}
