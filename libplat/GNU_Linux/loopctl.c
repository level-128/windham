/*
 * Loop device management: ioctl vs losetup fallback
 *
 * Compile-time selection (via CMake try_compile on <linux/loop.h>):
 *   - WINDHAM_NO_LOOP_IOCTL undefined: use kernel ioctl (preferred)
 *   - WINDHAM_NO_LOOP_IOCTL defined:   fall back to losetup command
 *
 *   If <linux/loop.h> is missing or does not define the required constants/structs,
 *   try_compile fails and the entire ioctl path is disabled at compile time.
 *   There is no runtime fallback from ioctl to losetup — it is decided at build time.
 *
 * ioctl path (init_file_device):
 *   1. /dev/loop-control  →  LOOP_CTL_GET_FREE  (find free loop device)
 *   2. LOOP_SET_FD        (attach backing file)
 *   3. LOOP_SET_STATUS64  (set LO_FLAGS_AUTOCLEAR; may fail with EPERM if
 *      CAP_SYS_RAWIO absent — tolerated, autoclear skipped but operation continues)
 *   4. LOOP_SET_BLOCK_SIZE (set sector/block size)
 *
 * ioctl path (free_loop):
 *   LOOP_CLR_FD to detach
 *
 * losetup fallback path (WINDHAM_NO_LOOP_IOCTL):
 *   init_file_device: exec_name("losetup", "-f", "--show", ..., "--sector-size", ...)
 *   free_loop:        exec_name("losetup", "-d", ...)
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fs.h>
#ifndef WINDHAM_NO_LOOP_IOCTL
#include <linux/loop.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <mntent.h>
#ifndef WINDHAM_NO_LOOP_IOCTL
#include <dirent.h>
#endif

#include "../../include/windham_const.h"
#include "../../include/cJSON.h"

#include "../../libsrc/chkhead.c"
#include "../../libsrc/srclib.c"
#include "blkid.c"

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


char * get_mount_point(const char * path) {
   FILE * mntfile = setmntent("/proc/mounts", "r");
   if (! mntfile) {
      perror("setmntent");
      return NULL;
   }

   struct mntent * mnt;
   size_t          longest_mountpoint_len = 0;
   char *          longest_mountpoint     = NULL;
   while ((mnt = getmntent(mntfile)) != NULL) {
      if (strstr(path, mnt->mnt_dir) == path) {
         if (longest_mountpoint_len < strlen(mnt->mnt_dir)) {
            longest_mountpoint_len = strlen(mnt->mnt_dir);
            free(longest_mountpoint); // longest_mountpoint is init to NULL
            longest_mountpoint = strdup(mnt->mnt_dir);
         }
      }
   }
   endmntent(mntfile);
   return longest_mountpoint;
}

void create_sparse_file(const char * path, size_t size) {
   struct stat   statbuf;
   struct statfs statfsbuf;
   int           fd;

   // Check if the file exists
   if (stat(path, &statbuf) == 0) {
      if (S_ISREG(statbuf.st_mode)) {
         print_warning(_("File already exists. Deleting it."));
         if (remove(path) != 0) {
            print_error(("Error deleting existing file: %s"), strerror(errno));
         }
      } else {
         print_error(_("Error: Path points to a special file type (not a regular file)."));
      }
   } else if (errno != ENOENT) {
      print_error(_("stat: syscall failed."));
   }

   // Create a temporary sparse file for testing support
   bool   is_supp_sparse = true;
   size_t test_size      = 2 * 1024 * 1024; // 2 MiB test size
   fd                    = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
   if (fd < 0) {
      print_error(_("Error creating file"));
   }

   // Check filesystems
   if (statfs(path, &statfsbuf) != 0) {
      perror("Error checking file system");
      windham_exit(1);
   }

   if (statfsbuf.f_type == TMPFS_MAGIC) {
      print_warning(_("Path is on tmpfs, might be deleted by the system.\n"));
   } else if (statfsbuf.f_type == NFS_SUPER_MAGIC || statfsbuf.f_type == SMB_SUPER_MAGIC ||
              statfsbuf.f_type == SMB2_SUPER_MAGIC) {
      print_warning(_("Path is on remote filesystems, performance may vary.\n"));
   } else if (statfsbuf.f_type == V9FS_MAGIC) {
      // Under WSL2, DrvFS is mounted under /mnt/*your drive letter*, using V9FS.
      ask_for_conformation(
         _(
            "It is likely that you are running Windham under WSL2 and you are trying to create a "
            "diskfile on MS Windows file system. Doing so will yield awful performance. It is "
            "strongly recommended to create a diskfile on Linux native file system."));
   }

   // End check filesystems

   if (ftruncate(fd, test_size) != 0) {
      close(fd);
      remove(path);
      print_error(_("Error allocating test size for sparse file"));
   }

   off_t data_offset = lseek(fd, 0, SEEK_DATA);

   if (! (data_offset == -1 && errno == ENXIO)) {
      ask_for_conformation(
         _(
            "File system does not support sparse files. Disk file will occupy its full size after "
            "creation. Space that are unused by the underlying filesystem in the diskfile will be "
            "wasted."));
      is_supp_sparse = false;
   }
   close(fd);

   if (remove(path) != 0) {
      perror("Error removing test file");
      windham_exit(1);
   }
   // End create a temporary sparse file for testing support

   // Ensure the file size is supported by the file system
   size_t filesystem_size           = statfsbuf.f_bsize * statfsbuf.f_blocks;
   size_t filesystem_available_size = statfsbuf.f_bsize * statfsbuf.f_bavail;
   if (is_supp_sparse) {
      if (size > filesystem_size) {
         print_warning(
            _("File size exceeds file system size (%zu bytes). I/O may fail due to "
               "insufficient space."),
            filesystem_size);
      }
   } else {
      if (size > filesystem_size) {
         print_error(_("File size exceeds maximum supported by file system (%zu bytes)."), filesystem_size);
      } else if (size > filesystem_available_size) {
         print_error(
            _("Error: File size exceeds available disk space (%zu bytes) and file system does not "
               "support sparse files.\n"),
            filesystem_available_size);
      }
   }

   fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
   if (fd < 0) {
      perror("Error creating file");
      windham_exit(1);
   }

   if (ftruncate(fd, size) != 0) {
      print_error_no_exit(_("Error creating file: %s"), strerror(errno));
      close(fd);
      remove(path); // do nothing when fail
      windham_exit(1);
   }

   close(fd);
   printf("Sparse file created successfully.\n");
}




struct stat open_and_check_file(const char * filename, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
   // STR_device.block_count and STR_device.block_size will be modified within this function
   // unless filename is not block device, which block_count and block_size remain uninit (this is because
   // under ISO C mode, it is impossible to detect block). Under this
   // case, the block_count and block_size will be set in function init_file_device, since right now
   // we donno whether the file will be mapped to loop.

   int fd = open(
      filename,
      is_readonly
         ? O_RDONLY
         : O_RDWR);
   if (fd == -1) {
      switch errno {
      case ENOENT:
         if (is_nofail) {
            printk("--nofail: Unable to find device\"%s\", device does not exist, exiting.", filename);
            exit(0);
         }
         print_error(_("The target \"%s\" does not exist."), filename);

      case ETXTBSY:
         print_error(_("The target is currently being read by the kernel. Conflict device or file?"));

      case EROFS:
         print_error(_("The target is on a read-only filesystem while Windham requires to modify it under this action."));

      case EACCES:
         print_error(_("Permission denied for file %s. Are you root?"), filename);

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
   if (S_ISCHR(st.st_mode) || S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode)) {
      print_error(_("target %s is a charcter device, socket or named pipe."), filename);
   }
   if (is_string_startwith(filename, "/sys/") == true) {
      if (! S_ISBLK(st.st_mode)) {
         print_error(_( "Non block device target from sysfs is unsupported."));
      }
   }
   if (! S_ISBLK(st.st_mode) && st.st_size < (ssize_t) sizeof(Data)) {
      print_error(_( "Wrong target? Target size (%li) is smaller than the header size."), st.st_size);
   }
   if (S_ISBLK(st.st_mode) && ioctl(fd, BLKGETSIZE, &STR_device->block_count) == -1) {
      print_error(_("Cannot get size for block device %s: %s"), filename, strerror(errno));
   }
   if (S_ISBLK(st.st_mode) && ioctl(fd, BLKPBSZGET, &STR_device->block_size) == -1) {
      print_error(_("Cannot get physical block size from %s: %s"), filename, strerror(errno));
   }
   if (S_ISBLK(st.st_mode) && ! (STR_device->block_size == 512 || STR_device->block_size == 1024 || STR_device->block_size == 2048
                                 ||
                                 STR_device->block_size == 4096)) {
      print_error(
         _("Unsupported block size for %s. Windham only supports 512b 1024b 2048b and 4096b block size. The device has"
            " block size %u. However, this is extremely uncommon."),
         filename,
         STR_device->block_size);
   }

   if (is_bypass_fs_check) {
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


   if (check_head((Data *) data) == false) {
      // probe filesystem when entropy not pass
      if (!is_blkid_available) {
         print_warning(_("Filesystem probe skipped: libblkid.so not loaded."));
         goto END_PROBE;
      }
      blkid_probe probe = p_blkid_new_probe();
      if (probe == NULL) {
         print_warning(_("Filesystem probe failed for %s."), filename);
         goto END_PROBE;
      }
      p_blkid_probe_set_device(probe, fd, 0, 0);
      if (p_blkid_do_probe(probe) == -1) {
         print_warning(_("Filesystem probe failed for %s."), filename);
         goto END_PROBE;
      }

      const char * fstype = "Unknown";
      size_t       len;

      int probe_result = p_blkid_probe_lookup_value(probe, "TYPE", &fstype, &len);

      if (probe_result == 0) {
         print_error(
            _("Invalid target; expected Windham target. target %s contains active %s filesystem. "
               "if the target contains a decoy partition, use \"--decoy\" to bypass filesystem check. "),
            filename,
            fstype);
      }
   END_PROBE:;
      print_warning(
         _("possibly invalid target; expected Windham target. target %s does not pass entropy check. "
            "Windham device has a random header and contains no pattern."),
         filename);
   }
END_FS_CHECK:;

   close(fd);
   return st;
}


void libloop_init_UUID_device(const char * UUID, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
   uint8_t _[16];
   if (generate_bytes_from_UUID(UUID, _) == false) { // check is UUID valid
      print_error(_("Invalid UUID format: %s"), UUID);
   }
   sprintf(STR_device->name, "/dev/disk/by-partuuid/%s", UUID);
   open_and_check_file(STR_device->name, is_readonly, is_nofail, is_bypass_fs_check);
}

void init_path_device(const char * path, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
   sprintf(STR_device->name, "/dev/disk/by-path/%s", path);
   open_and_check_file(STR_device->name, is_readonly, is_nofail, is_bypass_fs_check);
}

static DynBuf loop_device_names;

static void track_loop_device(const char *loop_path);

bool init_file_device(const char * filename, bool is_map_block, bool is_readonly, bool is_nofail, bool is_bypass_fs_check) {
    if (loop_device_names.elem_size == 0) {
        db_init(&loop_device_names, sizeof(char[FILENAME_MAX + 1]));
    }
   struct stat st = open_and_check_file(filename, is_readonly, is_nofail, is_bypass_fs_check);

   if (! S_ISBLK(st.st_mode) && is_map_block) {
      printf(_("Non block device deleted, creating loop.\n"));

#ifdef WINDHAM_NO_LOOP_IOCTL
      /* losetup fallback: invoke losetup -f --show <file> --sector-size <size> */
      char * exec_dir[]     = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
      char * dup_stdout     = NULL;
      size_t dup_stdout_len = 0;
      int    exec_ret_val   = 0;

      bool success = exec_name(
         "losetup",
         exec_dir,
         -1,
         &dup_stdout,
         &dup_stdout_len,
         &exec_ret_val,
         NMOBJ_exec_name_wait_child | NMOBJ_exec_name_dup_stdout_only,
         "-f",
         "--show",
         filename,
         "--sector-size",
         STRINGIFY(DEFAULT_BLOCK_SIZE),
         NULL);
      if (! success || exec_ret_val != 0) {
         print_error(_("Failed to setup loop device for %s"), filename);
      }
      dup_stdout[dup_stdout_len - 1] = 0; // returns with /n

      STR_device->is_loop = true;
      strcpy(STR_device->name, dup_stdout);
      free(dup_stdout);

      int fd = open(STR_device->name, O_RDONLY);
#else
      /* ioctl path: /dev/loop-control → LOOP_CTL_GET_FREE → LOOP_SET_FD
       * + LOOP_SET_STATUS64 + LOOP_SET_BLOCK_SIZE */
      // Open the backing file
      int file_fd = open(filename, is_readonly ? O_RDONLY : O_RDWR);
      if (file_fd < 0) {
         print_error(_("Failed to open backing file %s: %s"), filename, strerror(errno));
      }

      // Find a free loop device via /dev/loop-control
      int ctl_fd = open("/dev/loop-control", O_RDWR);
      if (ctl_fd < 0) {
         close(file_fd);
         print_error(_("Failed to open /dev/loop-control: %s"), strerror(errno));
      }

      int loop_nr = ioctl(ctl_fd, LOOP_CTL_GET_FREE);
      close(ctl_fd);
      if (loop_nr < 0) {
         close(file_fd);
         print_error(_("Failed to get free loop device: %s"), strerror(errno));
      }

      char loop_path[32];
      snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_nr);

      int loop_fd = open(loop_path, O_RDWR);
      if (loop_fd < 0) {
         close(file_fd);
         print_error(_("Failed to open loop device %s: %s"), loop_path, strerror(errno));
      }

      // Attach file to loop device
      if (ioctl(loop_fd, LOOP_SET_FD, file_fd) < 0) {
         close(loop_fd);
         close(file_fd);
         print_error(_("Failed to attach file to loop device %s: %s"), loop_path, strerror(errno));
      }

      // Set autoclear flag so the loop detaches when last reference closes.
      // LOOP_SET_STATUS64 may fail with EPERM if CAP_SYS_RAWIO is absent;
      // tolerated — autoclear is skipped but operation continues.
      struct loop_info64 info;
      memset(&info, 0, sizeof(info));
      info.lo_flags = LO_FLAGS_AUTOCLEAR;
      if (ioctl(loop_fd, LOOP_SET_STATUS64, &info) < 0 && errno != EPERM) {
         ioctl(loop_fd, LOOP_CLR_FD, 0);
         close(loop_fd);
         close(file_fd);
         print_error(_("Failed to set loop device status for %s: %s"), loop_path, strerror(errno));
      }

      // Set sector/block size
      if (ioctl(loop_fd, LOOP_SET_BLOCK_SIZE, DEFAULT_BLOCK_SIZE) < 0) {
         ioctl(loop_fd, LOOP_CLR_FD, 0);
         close(loop_fd);
         close(file_fd);
         print_error(_("Failed to set block size on loop device %s: %s"), loop_path, strerror(errno));
      }

      // dm-crypt will hold its own reference to the block device once mapped.
      // Close file_fd to avoid fd leak; loop_fd also stays open as a cleanup ref.
      close(file_fd);

      STR_device->is_loop = true;
      track_loop_device(loop_path);
      strncpy(STR_device->name, loop_path, sizeof(STR_device->name) - 1);
      STR_device->name[sizeof(STR_device->name) - 1] = '\0';

      int fd = loop_fd;
#endif

      if (ioctl(fd, BLKGETSIZE, &STR_device->block_count) == -1) {
         perror("ioctl(BLKGETSIZE)");
         windham_exit(1);
      }
      if (ioctl(fd, BLKPBSZGET, &STR_device->block_size) == -1) {
         perror("ioctl(BLKPBSZGET)");
         windham_exit(1);
      }

      // keep fd open, fin_device() detaches later
      return true;
   }
   STR_device->is_loop = false;
   strncpy(STR_device->name, filename, sizeof(STR_device->name));

   if (! S_ISBLK(st.st_mode) && is_map_block == false) {
      // when filename is a file, we need to set block_count as-if it is a block device
      // other code depends on block_count.
      STR_device->block_size = DEFAULT_BLOCK_SIZE;
      // capped to DEFAULT_BLOCK_SIZE, since losetup will discard unfilled block.
      STR_device->block_count = st.st_size / DEFAULT_BLOCK_SIZE * (DEFAULT_BLOCK_SIZE / 512);
   }
   return (bool) S_ISBLK(st.st_mode);
}


void init_device(
   const char * filename,
   bool         is_map_block,
   bool         is_readonly,
   bool         is_nofail,
   bool         is_bypass_fs_check,
   uintmax_t    disk_file_size,
   uintmax_t    block_size) {
   // error check
   assert(!(is_map_block && disk_file_size));          // a disk file cannot be mapped.
   assert(!((bool)disk_file_size ^ (bool)block_size)); // block_size must be zero if no disk file will be created.

   STR_device->is_loop = false; // print_error will release loop before create


   size_t max_filename_len = FILENAME_MAX + strlen("UUID=") - strlen("/dev/disk/by-partuuid/"); // longest
   if (strlen(filename) > max_filename_len) {
      print_error(_("the <device> is too long. max length is %lu bytes"), max_filename_len);
   }

   char * disk_file_msg = _("Disk file must not contain block device specific identifier: %s");

   if (is_string_startwith(filename, "UUID=")) {
      if (disk_file_size != 0) {
         print_error(disk_file_msg, "\"UUID=\".");
      }
      libloop_init_UUID_device(filename + strlen("UUID="), is_readonly, is_nofail, is_bypass_fs_check);
      STR_device->is_block = true;
   } else if (is_string_startwith(filename, "PATH=")) {
      if (disk_file_size != 0) {
         print_error(disk_file_msg, "\"PATH=\".");
      }
      init_path_device(filename + strlen("PATH="), is_readonly, is_nofail, is_bypass_fs_check);
      STR_device->is_block = true;
   } else if (is_string_startwith(filename, "DEV=")) {
      if (disk_file_size != 0) {
         print_error(disk_file_msg, "\"DEV=\".");
      }
      STR_device->is_block = init_file_device(
         filename + strlen("DEV="),
         is_map_block,
         is_readonly,
         is_nofail,
         is_bypass_fs_check);
   } else {
      if (disk_file_size != 0) {
         if (disk_file_size % block_size != 0) {
            printf(
               _("Disk file size does not align with the block size (%"PRIuMAX"). Shrink the file to the block size boundary."),
               block_size);
            disk_file_size = disk_file_size / block_size * block_size;
         }
         create_sparse_file(filename, disk_file_size);
      }
      STR_device->is_block = init_file_device(filename, is_map_block, is_readonly, is_nofail, is_bypass_fs_check);
   }
   assert((!STR_device->is_block && STR_device->is_loop) == false); // is loop but not block is impossible.
}

void free_loop(const char * name) {
#ifdef WINDHAM_NO_LOOP_IOCTL
   /* losetup fallback: invoke losetup -d <device> */
   char * exec_dir[]   = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
   int    exec_ret_val = 0;

   bool success = exec_name("losetup", exec_dir, -1, NULL, NULL, &exec_ret_val, NMOBJ_exec_name_wait_child, "-d", name, NULL);
   if (! success || exec_ret_val != 0) {
      print_warning(_("Failed to free loop device %s. Please run \"losetup -d %s\" manually."), name, name);
   }
#else
   /* ioctl path: LOOP_CLR_FD to detach */
   int loop_fd = open(name, O_RDWR);
   if (loop_fd < 0) {
      print_warning(_("Failed to open loop device %s for detach: %s. Please run \"losetup -d %s\" manually."), name, strerror(errno), name);
      return;
   }
   if (ioctl(loop_fd, LOOP_CLR_FD, 0) < 0) {
      print_warning(_("Failed to detach loop device %s: %s. Please run \"losetup -d %s\" manually."), name, strerror(errno), name);
   }
   close(loop_fd);
#endif
}


void fin_device() {
    for (size_t i = 0; i < db_count(&loop_device_names); i++) {
        free_loop((char *)db_get(&loop_device_names, i));
    }
    db_clear(&loop_device_names);
}

static void track_loop_device(const char *loop_path) {
    for (size_t i = 0; i < db_count(&loop_device_names); i++) {
        if (strcmp((char *)db_get(&loop_device_names, i), loop_path) == 0) return;
    }
    char path[FILENAME_MAX + 1];
    strncpy(path, loop_path, FILENAME_MAX);
    path[FILENAME_MAX] = '\0';
    db_add(&loop_device_names, path);
}


int check_device_topology(
   char *** parent,
   char *** child,
   char *** mount_points,
   size_t * parent_ret_len,
   size_t * child_ret_len,
   size_t * mount_points_len) {


   assert(!(*parent && *child));
   assert(!*mount_points);
   char * exec_dir[]     = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL};
   char * dup_stdout     = NULL;
   size_t dup_stdout_len = 0;
   int    exec_ret_val   = 0;
   bool   success;

   if (*parent) {
      success = exec_name(
         "lsblk",
         exec_dir,
         -1,
         &dup_stdout,
         &dup_stdout_len,
         &exec_ret_val,
         NMOBJ_exec_name_wait_child,
         **parent,
         "-J",
         "-p",
         NULL);
   } else {
      success = exec_name(
         "lsblk",
         exec_dir,
         -1,
         &dup_stdout,
         &dup_stdout_len,
         &exec_ret_val,
         NMOBJ_exec_name_wait_child,
         **child,
         "-s",
         "-J",
         "-p",
         NULL);
   }
   if (! success) {
      print_warning(
         _("Cannot determine device topology: Cannot call \"lsblk\". please make sure that the util-linux has installed."));
      *parent_ret_len = *child_ret_len = *mount_points_len = 0;
      return 1;
   }
   if (exec_ret_val != 0) {
      print_warning(_("Cannot determine device topology."));
      *parent_ret_len = *child_ret_len = *mount_points_len = 0;
      return 1;
   }

   cJSON * json = cJSON_Parse(dup_stdout);
   free(dup_stdout);
   cJSON * json_blockdevice    = cJSON_GetObjectItemCaseSensitive(json, "blockdevices");
   cJSON * json_device         = cJSON_GetArrayItem(json_blockdevice, 0);
   cJSON * json_mountpoints    = cJSON_GetObjectItemCaseSensitive(json_device, "mountpoints");
   bool    is_mountpoints_null = cJSON_IsNull(cJSON_GetArrayItem(json_mountpoints, 0));

   if (is_mountpoints_null) {
      *mount_points     = NULL;
      *mount_points_len = 0;
   } else {
      *mount_points_len = cJSON_GetArraySize(json_mountpoints);
      *mount_points     = malloc(sizeof(char *) * *mount_points_len);
      for (size_t i = 0; i < *mount_points_len; i ++) {
         char * temp        = cJSON_GetStringValue(cJSON_GetArrayItem(json_mountpoints, (int) i));
         (*mount_points)[i] = strdup(temp);
      }
   }

   char ** children_string;
   if (cJSON_HasObjectItem(json_device, "children")) {
      cJSON * json_children_array      = cJSON_GetObjectItemCaseSensitive(json_device, "children");
      size_t  json_children_array_size = cJSON_GetArraySize(json_children_array);
      children_string                  = malloc(json_children_array_size * sizeof(char *));

      for (size_t i = 0; i < json_children_array_size; i ++) {
         cJSON * json_children      = cJSON_GetArrayItem(json_children_array, (int) i);
         char *  json_children_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json_children, "name"));
         children_string[i]         = strdup(json_children_name);
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
}


void check_device_topology_free(char ** arr1, char ** arr2, size_t len_arr1, size_t len_arr2) {
   for (size_t i = 0; i < len_arr1; i ++) {
      free(arr1[i]);
   }
   free(arr1);
   for (size_t i = 0; i < len_arr2; i ++) {
      free(arr2[i]);
   }
   free(arr2);
}
