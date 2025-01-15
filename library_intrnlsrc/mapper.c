//
// Created by level-128 on 8/28/23.
//
#include <libdevmapper.h>
#include <linux/blkpg.h>
#include <linux/fs.h>
#include <sys/utsname.h>

#include <dlfcn.h>
#include "srclib.c"

#include <blkid/blkid.h>

// data
#ifndef INCL_MAPPER
#define INCL_MAPPER

typeof(dm_task_create)       *p_dm_task_create;
typeof(dm_task_set_name)     *p_dm_task_set_name;
typeof(dm_task_set_ro)       *p_dm_task_set_ro;
typeof(dm_task_set_uuid)     *p_dm_task_set_uuid;
typeof(dm_task_run)          *p_dm_task_run;
typeof(dm_task_destroy)      *p_dm_task_destroy;
typeof(dm_task_add_target)   *p_dm_task_add_target;
typeof(dm_task_update_nodes) *p_dm_task_update_nodes;
typeof(dm_task_deferred_remove) *p_dm_task_deferred_remove;

bool is_device_mapper_available;

typedef struct __attribute__((packed)) {
  uint8_t  hdr_sig[8];
  uint32_t hdr_revision;
#define GPT_HDR_REVISION 0x00010000
  uint32_t hdr_size;
  uint32_t hdr_crc_self;
  uint32_t __reserved;
  uint64_t hdr_lba_self;
  uint64_t hdr_lba_alt;
  uint64_t hdr_lba_start;
  uint64_t hdr_lba_end;
  uint8_t  hdr_uuid[16];
  uint64_t hdr_lba_table;
  uint32_t hdr_entries;
  uint32_t hdr_entsz;
  uint32_t hdr_crc_table;

  uint8_t padding[420];
} gpt_hdr;


typedef struct __attribute__((packed)) {
  uint8_t  ent_type[16];
  uint8_t  ent_uuid[16];
  uint64_t ent_lba_start;
  uint64_t ent_lba_end;
  uint64_t ent_attr;
  uint16_t ent_name[36]; /* UTF-16. */
} gpt_ent;


int entries_qsort_comp_func(const void *restrict x, const void *restrict y) {
  // x and y are small endian ints.
  const gpt_ent *restrict ent1 = x;
  const gpt_ent *restrict ent2 = y;
  // if the entry is empty, the ent_lba_end field is then 0.
  // ent_lba_end field should never be 0 if the entry is valid.
  if (le64toh(ent1->ent_lba_end) > le64toh(ent2->ent_lba_end)) {
    return -1; // before
  }
  if (le64toh(ent1->ent_lba_end) < le64toh(ent2->ent_lba_end)) {
    return 1; // after
  } else {
    return 0;
  }
}

typedef struct {
  gpt_ent  last_part;
  uint8_t  uuid[16];
  uint64_t lba_end;
  uint64_t lba_padding;
} Read_GPT_header_return;

bool read_GPT_header(const char *device, Read_GPT_header_return *return_) {
#ifndef IS_FRONTEND_ENTRY
  return false;
#else
  int fd = open(device, O_RDWR);
  if (fd == -1) {
    print_error(_("failed to detect GPT header on device %s"), device);
  }
  lseek(fd, 512, SEEK_SET); // skip protective MBR

  gpt_hdr hdr;
   
  if (read(fd, &hdr, sizeof(gpt_hdr)) != sizeof(gpt_hdr)){
    print_warning(_("Failed to detect GPT header on device %s"), device);
  };

  if (memcmp(hdr.hdr_sig, (uint8_t[]){69, 70, 73, 32, 80, 65, 82, 84}, sizeof(hdr.hdr_sig))) {
    close(fd);
    return false; // not GPT
  }
  uint8_t empty[sizeof(hdr.padding)] = {0};
  if (memcmp(empty, hdr.padding, sizeof(hdr.padding)) != 0 || hdr.__reserved != 0) {
    print_warning(_("invalid GPT header detected on device %s"), device);
    close(fd);
    return false;
  }

  lseek(fd, hdr.hdr_lba_table * 512, SEEK_SET); // move to lba table
  gpt_ent *gpt_ent_array = malloc(hdr.hdr_entries * hdr.hdr_entsz);

  if (read(fd, gpt_ent_array, hdr.hdr_entries * hdr.hdr_entsz) != hdr.hdr_entries * hdr.hdr_entsz){
    perror("read");
  };

  qsort(gpt_ent_array, hdr.hdr_entries, hdr.hdr_entsz, entries_qsort_comp_func);

  return_->last_part.ent_lba_end   = le64toh(gpt_ent_array->ent_lba_end);
  return_->last_part.ent_lba_start = le64toh(gpt_ent_array->ent_lba_start);
  return_->last_part.ent_attr      = gpt_ent_array->ent_attr;
  memcpy(return_->last_part.ent_uuid, gpt_ent_array->ent_uuid, 16);

  memcpy(&return_->uuid, hdr.hdr_uuid, sizeof(hdr.hdr_uuid));
  free(gpt_ent_array);

  return_->lba_end     = le64toh(hdr.hdr_lba_end);
  return_->lba_padding = return_->lba_end - return_->last_part.ent_lba_end;

  return true;
#endif
}


bool linear_map(const char *device, const char *name, const uint64_t start, const uint64_t size, const char uuid_str[37]) {
  char target_params[strlen(device) + strlen(" " STRINGIFY(UINT64_MAX)) + 1];

  // Create a new device mapper task
  struct dm_task *task = p_dm_task_create(DM_DEVICE_CREATE);
  if (task == NULL) {
    print_warning(_("cannot map partition %s according to the detected partition table on device %s."), name, device);
    return false;
  }

  assert(p_dm_task_set_name(task, name));
  assert(p_dm_task_set_uuid(task, uuid_str));

  // Set the target parameters
  sprintf(target_params, "%s %" PRIu64, device, start);
  if (!p_dm_task_add_target(task, 0, size, "linear", target_params)) {
    print_warning(_("cannot map partition %s according to the detected partition table on device %s."), name, device);
    p_dm_task_destroy(task);
    return false;
  }

  // Run the task
  int r = p_dm_task_run(task);
  if (!r) {
    print_warning(_("cannot map partition %s according to the detected partition table on device %s."), name, device);
    p_dm_task_destroy(task);
    return false;
  }
  p_dm_task_destroy(task);

  return true;
}

void remove_crypt_mapping_by_uuid(const char uuid_str[37]) {
#ifdef IS_FRONTEND_ENTRY
  struct dm_task *dmt;
  dmt = p_dm_task_create(DM_DEVICE_REMOVE);
  p_dm_task_set_uuid(dmt, uuid_str);
  if (!p_dm_task_run(dmt)) {
    print_warning(_("Failed when removing partition with UUID %s. Did you modified the partition table?"), uuid_str);
  }
  p_dm_task_destroy(dmt);
#else
  print_func_vars("uuid_str: %s", uuid_str);
#endif
}

void map_partition_table(const char *name, bool is_new_map) {
#ifdef IS_FRONTEND_ENTRY
  char device[strlen("/dev/mapper/") + strlen(name) + 1];
  sprintf(device, "/dev/mapper/%s", name);

  blkid_probe pr = blkid_new_probe_from_filename(device);
  if (!pr) {
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
    for (int i = 0; i < nparts; i++) {
      blkid_partition par   = blkid_partlist_get_partition(ls, i);
      int             parid = blkid_partition_get_partno(par);
      char            part_name[strlen(name) + strlen("-part" STRINGIFY(INTMAX_MAX)) + 1];
      printf("Partition %d: %d\n", i, parid);

      if (is_new_map) {
	blkid_loff_t start = blkid_partition_get_start(par);
	blkid_loff_t size  = blkid_partition_get_size(par);
	const char  *uuid  = blkid_partition_get_uuid(par);
	// Set the name of the new device

	sprintf(part_name, "%s-part%i", name, parid);
	linear_map(device, part_name, start, size, uuid);

      } else {
	const char *uuid = blkid_partition_get_uuid(par);
	remove_crypt_mapping_by_uuid(uuid);
      }
    }
  }
  blkid_free_probe(pr);
  p_dm_task_update_nodes();
#else
  print_func_vars("name: %s, is_new_map %i", name, is_new_map);
#endif
}


void convert_disk_key_to_hex_format(const uint8_t master_key[32], char key[HASHLEN * 2 + 1]) {
  const char *hex_chars = "0123456789abcdef";

  for (size_t i = 0; i < HASHLEN; ++i) {
    uint8_t byte   = master_key[i];
    key[i * 2]     = hex_chars[(byte >> 4) & 0xF];
    key[i * 2 + 1] = hex_chars[byte & 0xF];
  }

  key[HASHLEN * 2] = '\0'; // Null-terminate the string
}


void remove_crypt_mapping(const char *name, bool is_deferred_remove) {
#ifdef IS_FRONTEND_ENTRY
  if (!is_device_mapper_available) {
    print_error(_("Failed to close device mapping at \"/dev/mapper/%s\" due to missing device mapper library."), name);
  }


  map_partition_table(name, false);

  struct dm_task *dmt;
  dmt = p_dm_task_create(DM_DEVICE_REMOVE);
  p_dm_task_set_name(dmt, name);

  if (is_deferred_remove){
    if (!p_dm_task_deferred_remove(dmt)){
      print_error(_("failed to remove device %s. Is device a device-mapper target?"), name);
    }
  }
   
  if (!p_dm_task_run(dmt)) {
    print_error(_("failed to remove device %s. Is device a device-mapper target?"), name);
  }
  p_dm_task_destroy(dmt);

#else
  print_func_vars("name: %s", name);
#endif
}


int create_crypt_mapping(const char *device,
                         const char *name,
                         const char *enc_type,
                         const char *password,
                         char        uuid_str[37],
                         size_t      start_sector,
                         size_t      end_sector,
                         size_t      block_size,
                         bool        is_read_only,
                         bool        is_allow_discards,
                         bool        is_no_read_workqueue,
                         bool        is_no_write_workqueue) {
#ifdef IS_FRONTEND_ENTRY
  if (!is_device_mapper_available) {
    print_error(_("Failed to create device mapping due to missing device mapper library. \nDevice: %s\nUUID: %s"), device, uuid_str);
  }

  struct dm_task *dmt;
  // allow_discards
  // fix_padding must be used.

  // make crypt params
  int  param_cnt_crypt = 1;
  char params_crypt[540];
  char format_crypt[70] = "%s %s 0 %s %zu %i sector_size:%zu %s %s %s";
  if (is_allow_discards) {
    param_cnt_crypt++;
  }
  if (is_no_read_workqueue) {
    param_cnt_crypt++;
  }
  if (is_no_write_workqueue) {
    param_cnt_crypt++;
  }

  snprintf(params_crypt, sizeof(params_crypt), format_crypt, enc_type, password, device, start_sector, param_cnt_crypt, block_size,
	   is_allow_discards ? "allow_discards" : "", is_no_read_workqueue ? "no_read_workqueue" : "",
	   is_no_write_workqueue ? "no_write_workqueue" : "");

  if (!(dmt = p_dm_task_create(DM_DEVICE_CREATE))) {
    print_error(_("dm_task_create failed when mapping device %s"), name);
  }
  if (!p_dm_task_set_name(dmt, name)) {
    exit(EXIT_FAILURE);
  }
  if (!p_dm_task_set_uuid(dmt, uuid_str)) {
    exit(EXIT_FAILURE);
  }
  if (!p_dm_task_add_target(dmt, 0, end_sector - start_sector, "crypt", params_crypt)) {
    print_error(_("dm_task_add_target crypt failed when mapping device %s"), name);
  }
  if (is_read_only) {

    assert(p_dm_task_set_ro(dmt));
  }

  // dm_task_get_deps()
   
  if (!p_dm_task_run(dmt)) {
    print_error(_("p_dm_task_run failed when mapping crypt device %s. If this error occurs when trying to use kernel key for unlocking "
		  "the crypt device, make sure your SELinux or AppArmour policies"
		  " are properly set. To stop using kernel keyrings, use \"--nokeyring\""),
		name);
  }
  p_dm_task_destroy(dmt);

  p_dm_task_update_nodes();
#else
  print_func_vars("device: %s, name: %s, enc_type: %s, password: %s, uuid_str: %s", device, name, enc_type, password,  uuid_str);
#endif
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
void create_crypt_mapping_from_disk_key(const char *device,
                                        const char *target_name,
                                        const char *enc_type,

                                        const uint8_t disk_key[HASHLEN],
                                        uint8_t       uuid[16],

                                        size_t start_sector,
                                        size_t end_sector,
                                        size_t block_size,

                                        bool read_only,
                                        bool is_allow_discards,
                                        bool is_no_read_workqueue,
                                        bool is_no_write_workqueue,
                                        bool is_no_map_partition) {
  char password[HASHLEN * 2 + 1];
  convert_disk_key_to_hex_format(disk_key, password);

  char uuid_str[37];
  generate_UUID_from_bytes(uuid, uuid_str);

  create_crypt_mapping(device, target_name, enc_type, password, uuid_str, start_sector, end_sector, block_size, read_only,
		       is_allow_discards, is_no_read_workqueue, is_no_write_workqueue);

  if (!is_no_map_partition) {
    map_partition_table(target_name, true);
  }
}


void check_container(void) {
  char *container = NULL;
  if (getenv("container")) {
    container = "Flatpak";
  } else if (getenv("SNAP")) {
    container = "Snap";
  }
  if (container) {
    print_warning(_("Running inside a container (%s) is discouraged. Windham needs to interact with the Linux kernel, thus the  "
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
    printf("The target kernel version (%s) is older than the current system kernel version (%s). Consider recompiling Windham if needed.\n",
	   TARGET_KERNEL_VERSION, buffer.release);
  } else if (major_a < major_b || (major_a == major_b && minor_a < minor_b)) {
    printf("The target kernel version (%s) is newer than the current system kernel version (%s). This may leads "
	   "to compatibility issues. It is strongly recommended to recompile Windham on your local machine.\n",
	   TARGET_KERNEL_VERSION, buffer.release);
  }
}


void mapper_init() {
  check_container();
  void *handle = dlopen("libdevmapper.so", RTLD_LAZY);
  if (!handle) {
    print_warning(_("error loading libdevmapper.so, on-the-fly encryption cannot be supported. Please install 'libdevmapper' (under "
		    "debian-based distro) or 'device-mapper' (under "
		    "fedora/opensuse-based distro)"));
    is_device_mapper_available = false;
  } else {
    p_dm_task_create       = dlsym(handle, "dm_task_create");
    p_dm_task_set_name     = dlsym(handle, "dm_task_set_name");
    p_dm_task_set_ro       = dlsym(handle, "dm_task_set_ro");
    p_dm_task_set_uuid     = dlsym(handle, "dm_task_set_uuid");
    p_dm_task_run          = dlsym(handle, "dm_task_run");
    p_dm_task_destroy      = dlsym(handle, "dm_task_destroy");
    p_dm_task_add_target   = dlsym(handle, "dm_task_add_target");
    p_dm_task_update_nodes = dlsym(handle, "dm_task_update_nodes");
    p_dm_task_deferred_remove = dlsym(handle, "dm_task_deferred_remove");
    is_device_mapper_available = true;
  }
}

#endif
