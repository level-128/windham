#include <assert.h>
#include <cJSON.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <blkid/blkid.h>
#include <windham_const.h>

#include "chkhead.c"

#include "srclib.c"

#define CHECK_DEVICE_TOPOLOGY(device, device_path, node, CODE_EXEC_IF_RET) \
  char *device_loc;							\
  if (strcmp(device_path, "") != 0) {					\
    device_loc = malloc(strlen(device) + strlen(device_path "/") + 1);	\
    sprintf(device_loc, device_path "/%s", (device));			\
  } else {								\
    device_loc = (char *) (device);					\
  }									\
  char **parent       = NULL;						\
  char **child        = NULL;						\
  node                = (char **) &device_loc;				\
  char **mount_points = NULL;						\
  size_t parent_ret_len, child_ret_len, mount_points_len = 0;		\
									\
  int retval = check_device_topology(&parent, &child, &mount_points, &parent_ret_len, &child_ret_len, &mount_points_len); \
  if (strcmp(device_path, "") != 0) {					\
    free(device_loc);							\
  }									\
  if (retval == 0) {							\
    CODE_EXEC_IF_RET							\
      }


#define CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(comp_var, CODE_CMP_COND, pri_arr, CODE_PRI_ONE_RETLEN, CODE_PRI_MUL_RETLEN) \
  if (comp_var CODE_CMP_COND) {						\
    if (comp_var == 1 || strcmp(#CODE_PRI_MUL_RETLEN, "(\"\")") == 0) {	\
      print_error_no_exit CODE_PRI_ONE_RETLEN;				\
    } else {								\
      print_error_no_exit CODE_PRI_MUL_RETLEN;				\
      for (size_t i = 0; i < comp_var; i++) {				\
	printf("\033[1;33m - %s\033[0m\n", ((char **) pri_arr)[i]);	\
      }									\
    }									\
    windham_exit(1);							\
  }


#define CHECK_DEVICE_TOPOLOGY_FREE(res)					\
  if (retval == 0) {							\
    check_device_topology_free(res, mount_points, res##_ret_len, mount_points_len); \
  }

#ifndef INCL_LIBLOOP
#define INCL_LIBLOOP


// STR_device.block_count and STR_device.block_size will be modified within this function
// unless filename is not block device, which block_count and block_size remain uninit.
struct stat open_and_check_file(const char * filename, bool is_readonly, bool is_nofail, bool is_bypass_fs_check){
  int fd = open(filename, is_readonly ? O_RDONLY : O_RDWR);
  if (fd == -1){
    switch errno{
	case ENOENT:
	  if (is_nofail) {
	    printk("--nofail: Unable to find device\"%s\", device does not exist, exiting.", filename);
	    exit(0);
	  }
	  print_error(_("The target does not exist."));
	  break;
	    
	  case ETXTBSY:
	    print_error(_("The target is currently being read by the kernel. Conflict device or file?"));
	    break;
	    
	    case EROFS:
	      print_error(_("The target is on a read-only filesystem while Windham requires to modify it under this action."));
	      break;
	    
	      case EACCES:
		print_error(_("Permission denied. Are you root?"));
		break;
	    
		default:
		  print_error(_("Cannot open target %s: %s"), filename, strerror(errno));
      }
  }

    
  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("Error stating file");
    close(fd);
    exit(1);
  }
  if (S_ISDIR(st.st_mode)) {
    print_error(_("Target %s is a directory."), filename);
  }
  if (S_ISCHR(st.st_mode) || S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode)){
    print_error(_("target %s is a charcter device, socket or named pipe."), filename);
  }
  if (is_string_startwith(filename, "/sys/") == true) {
    if (!S_ISBLK(st.st_mode)) {
      print_error(_( "Non block device target from sysfs is unsupported."));
    }
  }
  if (!S_ISBLK(st.st_mode) && st.st_size < (ssize_t)sizeof(Data)) {
    print_error(_( "Wrong target? Target size (%li) is smaller than the header size."), st.st_size);
  }
  if (S_ISBLK(st.st_mode) && ioctl(fd, BLKGETSIZE, &STR_device->block_count) == -1){
    print_error(_("Cannot get size for block device %s: %s"), filename, strerror(errno));
  }
  if (S_ISBLK(st.st_mode) && ioctl(fd, BLKPBSZGET, &STR_device->block_size) == -1) {
    print_error(_("Cannot get physical block size from %s: %s"), filename, strerror(errno));
  }
  if (S_ISBLK(st.st_mode) && !(STR_device->block_size == 512 || STR_device->block_size == 1024 || STR_device->block_size == 2048 ||
			       STR_device->block_size == 4096)) {
    print_error(_("Unsupported block size for %s. Windham only supports 512b 1024b 2048b and 4096b block size. The device has"
		  " block size %u. However, this is extremely uncommon."), filename, STR_device->block_size);
  }

  if (is_bypass_fs_check){
    goto END_FS_CHECK;
  }
   
  // quick entropy test
  uint8_t data[sizeof(Data)];

  size_t total_read = 0;
  while (total_read < sizeof(data)) {
    ssize_t bytes_read = read(fd, data + total_read, sizeof(data) - total_read);
    if (bytes_read < 0) {
      if (errno == EINTR) {
	continue;
      }

      if (errno == EIO) {
	print_error(_("IO error for target %s: Bad drive or race condition with kernel space?"), filename);
      }

      perror("Error reading file");
      close(fd);
      exit(1);
    } else if (bytes_read == 0) {
      // End of file
      fprintf(stderr, "Error: Unexpected end of file.\n");
      close(fd);
      exit(1);
    }
    total_read += bytes_read;
  }

    
  if (check_head(*(Data *)data) == false){
    // probe filesystem when entropy not pass
    blkid_probe probe = blkid_new_probe();
    if (probe == NULL){
      print_warning(_("Filesystem probe failed for %s."), filename);
      goto END_PROBE;
    }
    blkid_probe_set_device(probe, fd, 0, 0);
    if (blkid_do_probe(probe) == -1) {
      print_warning(_("Filesystem probe failed for %s."), filename);
      goto END_PROBE;
    }

    const char *  fstype = "Unknown";
    size_t       len;

    int probe_result = blkid_probe_lookup_value(probe, "TYPE", &fstype, &len);
      
    if (probe_result == 0){
      print_error(
		  _("Invalid target; expected Windham target. target %s contains active %s filesystem. "
		    "if the target contains a decoy partition, use \"--decoy\" to bypass filesystem check. "),
		  filename,
		  fstype);
    }
  END_PROBE:;
    print_error(
		_("Invalid target; expected Windham target. target %s does not pass entropy check. "
		  "Windham device has a random header and contains no pattern."), filename);
      
      
  }

 END_FS_CHECK:;
    
  close(fd);
  return st;
    
}


void init_UUID_device(const char *UUID, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
  uint8_t _[16];
  if (generate_bytes_from_UUID(UUID, _) == false) { // check is UUID valid
    print_error(_("Invalid UUID format: %s"), UUID);
  }
  sprintf(STR_device->name, "/dev/disk/by-partuuid/%s", UUID);
  open_and_check_file(STR_device->name, is_readonly, is_nofail, is_bypass_fs_check);
}

void init_path_device(const char *path, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
  sprintf(STR_device->name, "/dev/disk/by-path/%s", path);
  open_and_check_file(STR_device->name, is_readonly, is_nofail, is_bypass_fs_check);
}

bool init_file_device(const char *filename, bool is_create_loop, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
  struct stat st =    open_and_check_file(filename, is_readonly, is_nofail, is_bypass_fs_check);

  if (!S_ISBLK(st.st_mode) && is_create_loop) {
    char  *exec_dir[]     = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
    char  *dup_stdout     = NULL;
    size_t dup_stdout_len = 0;
    int    exec_ret_val   = 0;

    printf(_("Non block device deleted, creating loop.\n"));

    bool success = exec_name("losetup", exec_dir, -1, &dup_stdout, &dup_stdout_len, &exec_ret_val,
			     NMOBJ_exec_name_wait_child | NMOBJ_exec_name_dup_stdout_only, "-f", "--show", filename, "--sector-size",
			     STRINGIFY(DEFAULT_BLOCK_SIZE), NULL);
    if (!success || exec_ret_val != 0) {
      print_error(_("Failed to setup loop device for %s"), filename);
    }
    dup_stdout[dup_stdout_len - 1] = 0; // returns with /n

    STR_device->is_loop = true;
    memcpy(STR_device->name, dup_stdout, dup_stdout_len);

    int fd = open(STR_device->name, O_RDONLY);

    if (ioctl(fd, BLKGETSIZE, &STR_device->block_count) == -1){
      perror("ioctl(BLKGETSIZE)"); // unlikely to fail.
      windham_exit(1);
    }
    if (ioctl(fd, BLKPBSZGET, &STR_device->block_size) == -1) {
      perror("ioctl(BLKPBSZGET)");
      windham_exit(1);
    }

    close(fd);
	 
    return true;

  }
  STR_device->is_loop = false;
  strncpy(STR_device->name, filename, sizeof(STR_device->name));
   
  if (!S_ISBLK(st.st_mode) && is_create_loop == false){
    // when filename is a file, we need to set block_count as-if it is a block device
    // other code depends on block_count.
    STR_device->block_size = DEFAULT_BLOCK_SIZE;
    // capped to DEFAULT_BLOCK_SIZE, since losetup will discard unfilled block.
    STR_device->block_count = st.st_size / DEFAULT_BLOCK_SIZE * (DEFAULT_BLOCK_SIZE / 512); 
  }
   
  return (bool) S_ISBLK(st.st_mode);
}


void init_device(const char *filename, bool is_create_loop, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
  STR_device->is_loop = false; // print_error will release loop before create
  bool __attribute__((unused)) is_block; // 

  size_t max_filename_len = PATH_MAX + strlen("UUID=") - strlen("/dev/disk/by-partuuid/") - 1; // longest
  if (strlen(filename) > max_filename_len) {
    print_error(_("the <device> is too long. max length is %lu bytes"), max_filename_len);
  }

  if (is_string_startwith(filename, "UUID=")) {
    init_UUID_device(filename + strlen("UUID="), is_readonly, is_nofail, is_bypass_fs_check);
    is_block = true;
  } else if (is_string_startwith(filename, "PATH=")) {
    init_path_device(filename + strlen("PATH="), is_readonly, is_nofail, is_bypass_fs_check);
    is_block = true;
  } else if (is_string_startwith(filename, "DEV=")) {
    is_block = init_file_device(filename + strlen("DEV="), is_create_loop, is_readonly, is_nofail, is_bypass_fs_check);
  } else {
    is_block = init_file_device(filename, is_create_loop, is_readonly, is_nofail, is_bypass_fs_check);
  }

}

void free_loop(const char *name) {
  char *exec_dir[]   = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
  int   exec_ret_val = 0;

  bool success = exec_name("losetup", exec_dir, -1, NULL, NULL, &exec_ret_val, NMOBJ_exec_name_wait_child, "-d", name, NULL);
  if (!success || exec_ret_val != 0) {
    print_warning(_("Failed to free loop device %s. Please run \"losetup -d %s\" manually."), name, name);
  }
}


void fin_device() {
  if (STR_device->is_loop == true) {
    free_loop(STR_device->name);
  }
}


int check_device_topology(
			  char ***parent, char ***child, char ***mount_points, size_t *parent_ret_len, size_t *child_ret_len, size_t *mount_points_len) {
#ifdef WINDHAM_USE_NULL_MALLOC
  *parent_ret_len = *child_ret_len = *mount_points_len = 0;
  return 1;
#else
  assert(!(*parent && *child));
  assert(!*mount_points);
  char  *exec_dir[]     = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL};
  char  *dup_stdout     = NULL;
  size_t dup_stdout_len = 0;
  int    exec_ret_val   = 0;
  bool   success;

  if (*parent) {
    success = exec_name("lsblk", exec_dir, -1, &dup_stdout, &dup_stdout_len, &exec_ret_val, NMOBJ_exec_name_wait_child, **parent, "-J", "-p",
			NULL);
  } else {
    success = exec_name("lsblk", exec_dir, -1, &dup_stdout, &dup_stdout_len, &exec_ret_val, NMOBJ_exec_name_wait_child, **child, "-s", "-J",
			"-p", NULL);
  }
  if (!success) {
    print_warning(_("Cannot determine device topology: Cannot call \"lsblk\". please make sure that the util-linux has installed."));
    *parent_ret_len = *child_ret_len = *mount_points_len = 0;
    return 1;
  }
  if (exec_ret_val != 0) {
    print_warning(_("Cannot determine device topology."));
    *parent_ret_len = *child_ret_len = *mount_points_len = 0;
    return 1;
  }

  cJSON *json = cJSON_Parse(dup_stdout);
  free(dup_stdout);
  cJSON *json_blockdevice    = cJSON_GetObjectItemCaseSensitive(json, "blockdevices");
  cJSON *json_device         = cJSON_GetArrayItem(json_blockdevice, 0);
  cJSON *json_mountpoints    = cJSON_GetObjectItemCaseSensitive(json_device, "mountpoints");
  bool   is_mountpoints_null = cJSON_IsNull(cJSON_GetArrayItem(json_mountpoints, 0));

  if (is_mountpoints_null) {
    *mount_points     = NULL;
    *mount_points_len = 0;
  } else {
    *mount_points_len = cJSON_GetArraySize(json_mountpoints);
    *mount_points     = malloc(sizeof(char *) * *mount_points_len);
    for (size_t i = 0; i < *mount_points_len; i++) {
      char *temp         = cJSON_GetStringValue(cJSON_GetArrayItem(json_mountpoints, (int) i));
      (*mount_points)[i] = strdup(temp);
    }
  }

  char **children_string;
  if (cJSON_HasObjectItem(json_device, "children")) {
    cJSON *json_children_array      = cJSON_GetObjectItemCaseSensitive(json_device, "children");
    size_t json_children_array_size = cJSON_GetArraySize(json_children_array);
    children_string                 = malloc(json_children_array_size);

    for (size_t i = 0; i < json_children_array_size; i++) {
      cJSON *json_children      = cJSON_GetArrayItem(json_children_array, (int) i);
      char  *json_children_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json_children, "name"));
      children_string[i]        = strdup(json_children_name);
    }
    if (*parent) {
      *child         = children_string;
      *child_ret_len = json_children_array_size;
    } else {
      *parent         = children_string;
      *parent_ret_len = json_children_array_size;
    }
  } else {
    *parent_ret_len = *child_ret_len = 0;
  }
  cJSON_free(json);
  return 0;
#endif
}


void check_device_topology_free(char **arr1, char **arr2, size_t len_arr1, size_t len_arr2) {
  for (size_t i = 0; i < len_arr1; i++) {
    free(arr1[i]);
  }
  free(arr1);
  for (size_t i = 0; i < len_arr2; i++) {
    free(arr2[i]);
  }
  free(arr2);
}

#endif
