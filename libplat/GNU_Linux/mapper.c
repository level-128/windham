#include <libdevmapper.h>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <stdbool.h>

bool linear_map(const char * device, const char * name, const uint64_t start, const uint64_t size, const char uuid_str[37]) {

   char target_params[strlen(device) + strlen(" " STRINGIFY(UINT64_MAX)) + 1];

   // Create a new device mapper task
   struct dm_task * task = p_dm_task_create(DM_DEVICE_CREATE);
   if (task == NULL) {
      print_warning(_("cannot map partition %s according to the detected partition table on device %s."), name, device);
      return false;
   }

   assert(p_dm_task_set_name(task, name));
   assert(p_dm_task_set_uuid(task, uuid_str));

   // Set the target parameters
   sprintf(target_params, "%s %" PRIu64, device, start);
   if (! p_dm_task_add_target(task, 0, size, "linear", target_params)) {
      print_warning(_("cannot map partition %s according to the detected partition table on device %s."), name, device);
      p_dm_task_destroy(task);
      return false;
   }

   // Run the task
   int r = p_dm_task_run(task);
   if (! r) {
      print_warning(_("cannot map partition %s according to the detected partition table on device %s."), name, device);
      p_dm_task_destroy(task);
      return false;
   }
   p_dm_task_destroy(task);

   return true;
}


void remove_crypt_mapping_by_uuid(const char uuid_str[37]) {
   struct dm_task * dmt;
   dmt = p_dm_task_create(DM_DEVICE_REMOVE);
   p_dm_task_set_uuid(dmt, uuid_str);
   if (! p_dm_task_run(dmt)) {
      print_warning(_("Failed when removing partition with UUID %s. Did you modified the partition table?"), uuid_str);
   }
   p_dm_task_destroy(dmt);
}


void map_partition_table(const char * name, bool is_new_map) {
   char device[strlen("/dev/mapper/") + strlen(name) + 1];
   sprintf(device, "/dev/mapper/%s", name);

   blkid_probe pr = blkid_new_probe_from_filename(device);
   if (! pr) {
      perror("Failed to open device");
      blkid_free_probe(pr);
      return;
   }


   blkid_do_probe(pr);
   const blkid_partlist ls = blkid_probe_get_partitions(pr);
   if (ls != NULL) {
      // partition table present

      int nparts = blkid_partlist_numof_partitions(ls);

      printf("Number of partitions: %d\n", nparts);
      for (int i = 0; i < nparts; i ++) {
         blkid_partition par   = blkid_partlist_get_partition(ls, i);
         int             parid = blkid_partition_get_partno(par);
         char            part_name[strlen(name) + strlen("-part" STRINGIFY(INTMAX_MAX)) + 1];
         printf("Partition %d: %d\n", i, parid);

         if (is_new_map) {
            blkid_loff_t start = blkid_partition_get_start(par);
            blkid_loff_t size  = blkid_partition_get_size(par);
            const char * uuid  = blkid_partition_get_uuid(par);
            // Set the name of the new device

            sprintf(part_name, "%s-part%i", name, parid);
            linear_map(device, part_name, start, size, uuid);
         } else {
            const char * uuid = blkid_partition_get_uuid(par);
            remove_crypt_mapping_by_uuid(uuid);
         }
      }
   }
   blkid_free_probe(pr);
   p_dm_task_update_nodes();
}




void remove_crypt_mapping(const char * name, bool is_deferred_remove) {
   if (! is_device_mapper_available) {
      print_error(_("Failed to close device mapping at \"/dev/mapper/%s\" due to missing device mapper library."), name);
   }


   map_partition_table(name, false);

   struct dm_task * dmt;
   dmt = p_dm_task_create(DM_DEVICE_REMOVE);
   p_dm_task_set_name(dmt, name);

   if (is_deferred_remove) {
      if (! p_dm_task_deferred_remove(dmt)) {
         print_error(_("failed to remove device %s. Is device a device-mapper target?"), name);
      }
   }

   if (! p_dm_task_run(dmt)) {
      print_error(_("failed to remove device %s. Is device a device-mapper target?"), name);
   }
   p_dm_task_destroy(dmt);
}


int create_crypt_mapping(
   const char * device,
   const char * name,
   const char * enc_type,
   const char * password,
   char         uuid_str[37],
   size_t       start_sector,
   size_t       end_sector,
   size_t       block_size,
   bool         is_read_only,
   bool         is_allow_discards,
   bool         is_no_read_workqueue,
   bool         is_no_write_workqueue) {
   if (! is_device_mapper_available) {
      print_error(
         _("Failed to create device mapping due to missing device mapper library. \nDevice: %s\nUUID: %s"),
         device,
         uuid_str);
   }

   struct dm_task * dmt;
   // allow_discards
   // fix_padding must be used.

    // make crypt params
    int  param_cnt_crypt = 1; // sector_size is always present
    char params_crypt[540];
    char format_crypt[96] = "%s %s 0 %s %zu %i sector_size:%zu";
    char *p = format_crypt + strlen(format_crypt);
    if (is_allow_discards) {
       param_cnt_crypt++;
       p += snprintf(p, sizeof(format_crypt) - (p - format_crypt), " allow_discards");
    }
    if (is_no_read_workqueue) {
       param_cnt_crypt++;
       p += snprintf(p, sizeof(format_crypt) - (p - format_crypt), " no_read_workqueue");
    }
    if (is_no_write_workqueue) {
       param_cnt_crypt++;
       p += snprintf(p, sizeof(format_crypt) - (p - format_crypt), " no_write_workqueue");
    }

    snprintf(
       params_crypt,
       sizeof(params_crypt),
       format_crypt,
       enc_type,
       password,
       device,
       start_sector,
       param_cnt_crypt,
       block_size);
 
    if (! (dmt = p_dm_task_create(DM_DEVICE_CREATE))) {
      print_error(_("dm_task_create failed when mapping device %s"), name);
   }
   if (! p_dm_task_set_name(dmt, name)) {
      p_dm_task_destroy(dmt);
      print_error(_("dm_task_set_name failed when mapping device %s"), name);
   }
   if (! p_dm_task_set_uuid(dmt, uuid_str)) {
      p_dm_task_destroy(dmt);
      print_error(_("dm_task_set_uuid failed when mapping device %s"), name);
   }
    if (! p_dm_task_add_target(dmt, 0, end_sector - start_sector, "crypt", params_crypt)) {
       print_error(_("dm_task_add_target crypt failed when mapping device %s"), name);
    }
   if (is_read_only) {
      assert(p_dm_task_set_ro(dmt));
   }

   // dm_task_get_deps()

   if (! p_dm_task_run(dmt)) {
      print_error(
         _("p_dm_task_run failed when mapping crypt device %s. If this error occurs when trying to use kernel key for unlocking "
            "the crypt device, make sure your SELinux or AppArmour policies"
            " are properly set. To stop using kernel keyrings, use \"--nokeyring\""),
         name);
   }
   p_dm_task_destroy(dmt);

   p_dm_task_update_nodes();
   return 0;
}


/**
 * @brief Create a crypt mapping from a disk key
 *
 * This function creates a crypt mapping from a disk key. The crypt mapping is created using the provided device, target name,
 * encryption metadata, disk key, UUID, and other options. The function first converts the disk key to a hexadecimal format,
 * generates a UUID string from the UUID bytes, and then calls the create_crypt_mapping function to create the crypt mapping.
 * If the "is_no_map_partition" option is false, the function also attempts to detect and map the partition table under the specified target
 * location.
 *
 * @param device The device to create the crypt mapping on
 * @param target_name The target name of the crypt mapping
 * @param metadata The encryption metadata
 * @param disk_key The disk key
 * @param uuid The UUID
 * @param read_only Flag indicating if the crypt mapping should be read-only
 * @param is_allow_discards Flag indicating if discards are allowed
 * @param is_no_read_workqueue Flag indicating if read workqueue is disabled
 * @param is_no_write_workqueue Flag indicating if write workqueue is disabled
 * @param is_no_map_partition Flag indicating if partition mapping should be skipped
 */
void create_crypt_mapping_from_disk_key(
   const char * device,
   const char * target_name,
   const char * enc_type,

   const uint8_t *disk_key,
   size_t         disk_key_size,
   uint8_t        uuid[16],

   size_t start_sector,
   size_t end_sector,
   size_t block_size,

   bool read_only,
   bool is_allow_discards,
   bool is_no_read_workqueue,
   bool is_no_write_workqueue,
   bool is_no_map_partition) {
   char *password = malloc(disk_key_size * 2 + 1);
   if (!password) { 
      perror("malloc");
      exit(1);
   }
   convert_disk_key_to_hex_format(disk_key, disk_key_size, password);

   char uuid_str[37];
   generate_UUID_from_bytes(uuid, uuid_str);

   create_crypt_mapping(
      device,
      target_name,
      enc_type,
      password,
      uuid_str,
      start_sector,
      end_sector,
      block_size,
      read_only,
      is_allow_discards,
      is_no_read_workqueue,
      is_no_write_workqueue);
   free(password);

   if (! is_no_map_partition) {
      map_partition_table(target_name, true);
   }
}


int try_create_crypt_mapping(const char * file_name, const char * enc_type, const char * tmp_name) {
   if (! is_device_mapper_available) {
      return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
   }

   struct dm_task * dmt;

   char params_crypt[540];

   snprintf(
      params_crypt,
      sizeof(params_crypt),
      "%s e8cfa3dbfe373b536be43c5637387786c01be00ba5f730aacb039e86f3eb72f3 0 %s 0",
      enc_type,
      file_name);



   char name[] = "windham-tmp-XXXXXX";
   memcpy(name + strlen("windham-tmp-"), tmp_name, 6);

   if (! (dmt = p_dm_task_create(DM_DEVICE_CREATE))) {
      return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
   }

   if (! p_dm_task_set_name(dmt, name)) {
      p_dm_task_destroy(dmt);
      return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
   }
   if (! p_dm_task_add_target(dmt, 0, 8, "crypt", params_crypt)) {
      p_dm_task_destroy(dmt);
      return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
   }

   if (! p_dm_task_run(dmt)) {
      p_dm_task_destroy(dmt);
      return EMOBJ_try_create_crypt_mapping_FAILED_MAPPING;
   }
   p_dm_task_destroy(dmt);

   p_dm_task_update_nodes();

   dmt = p_dm_task_create(DM_DEVICE_REMOVE);
   p_dm_task_set_name(dmt, name);

   if (! p_dm_task_run(dmt)) {
      p_dm_task_destroy(dmt);
      return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
   }
   p_dm_task_destroy(dmt);

   p_dm_task_update_nodes();

   return EMOBJ_try_create_crypt_mapping_OK;
}


void check_environment(void) {
   char * container = NULL;
   if (getenv("container")) {
      container = "Flatpak";
   } else if (getenv("SNAP")) {
      container = "Snap";
   }
   if (container) {
      print_warning(
         _("Running inside a container (%s) is discouraged. Windham needs to interact with the Linux kernel, thus the  "
            "container may render the program malfunction."),
         container);
   }
   struct utsname buffer;

   if (uname(&buffer) == -1) {
      return;
   }

   int major_a = 0, minor_a = 0;
   sscanf(buffer.release, "%d.%d", &major_a, &minor_a);

   int major_b = 0, minor_b = 0;
   sscanf(TARGET_KERNEL_VERSION, "%d.%d", &major_b, &minor_b);

   if (major_a > major_b || (major_a == major_b && minor_a > minor_b)) {
      printf(
         "The target kernel version (%s) is older than the current system kernel version (%s). Consider recompiling Windham if needed.\n",
         TARGET_KERNEL_VERSION,
         buffer.release);
   } else if (major_a < major_b || (major_a == major_b && minor_a < minor_b)) {
      printf(
         "The target kernel version (%s) is newer than the current system kernel version (%s). This may leads "
         "to compatibility issues. It is strongly recommended to recompile Windham on your local machine.\n",
         TARGET_KERNEL_VERSION,
         buffer.release);
   }
}


void mapper_init() {
   check_environment();
   void * handle = dlopen("libdevmapper.so", RTLD_LAZY);
   if (! handle) {
      print_warning(
         _("error loading libdevmapper.so, on-the-fly encryption cannot be supported. Please install 'libdevmapper' (under "
            "debian-based distro) or 'device-mapper' (under "
            "fedora/opensuse-based distro)"));
      is_device_mapper_available = false;
   } else {
      p_dm_task_create           = (struct dm_task * (*)(int)) dlsym(handle, "dm_task_create");
      p_dm_task_set_name         = (int (*)(struct dm_task *, const char *)) dlsym(handle, "dm_task_set_name");
      p_dm_task_set_ro           = dlsym(handle, "dm_task_set_ro");
      p_dm_task_set_uuid         = dlsym(handle, "dm_task_set_uuid");
      p_dm_task_run              = dlsym(handle, "dm_task_run");
      p_dm_task_destroy          = dlsym(handle, "dm_task_destroy");
      p_dm_task_add_target       = dlsym(handle, "dm_task_add_target");
      p_dm_task_update_nodes     = dlsym(handle, "dm_task_update_nodes");
       p_dm_task_deferred_remove  = dlsym(handle, "dm_task_deferred_remove");
       p_dm_task_get_names       = dlsym(handle, "dm_task_get_names");
       p_dm_task_get_info        = dlsym(handle, "dm_task_get_info");
       p_dm_task_get_uuid        = dlsym(handle, "dm_task_get_uuid");
       p_dm_task_get_deps        = dlsym(handle, "dm_task_get_deps");
       p_dm_get_next_target      = dlsym(handle, "dm_get_next_target");
       is_device_mapper_available = true;
   }
}

