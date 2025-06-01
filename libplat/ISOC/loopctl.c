// pure ISO C implementation of libloop.

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "../../include/windham_const.h"
#include "../../include/cJSON.h"

#include "../../libsrc/chkhead.c"
#include "../../libsrc/srclib.c"


#define CHECK_DEVICE_TOPOLOGY(device, device_path, node, CODE_EXEC_IF_RET)

#define CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(comp_var, CODE_CMP_COND, pri_arr, CODE_PRI_ONE_RETLEN, CODE_PRI_MUL_RETLEN)

#define CHECK_DEVICE_TOPOLOGY_FREE(res)


void create_file(const char *path, size_t size) {
   FILE *test = fopen(path, "rb");
   if (test) {
      print_warning(_("File already exists. Deleting it."))
      fclose(test);
   }

   FILE *file = fopen(path, "wb");
   if (!file) {
      fprintf(stderr, "Error opening file: %s\n", strerror(errno));
      return;
   }

   if (size == 0) {
      fclose(file);
      return;
   }

   const size_t target_pos = size - 1;
   size_t remaining = target_pos;
   int seek_result = 0;

   while (remaining > 0) {
      long chunk = (remaining > (size_t)LONG_MAX) ? LONG_MAX : (long)remaining;
      seek_result = fseek(file, chunk, SEEK_CUR);

      if (seek_result != 0) {
         fprintf(stderr, "fseek failed: %s (remaining=%zu)\n",
                 strerror(errno), remaining);
         fclose(file);
         remove(path);
         return;
      }
      remaining -= (size_t)chunk;
   }

   if (fputc(0, file) == EOF) {
      fprintf(stderr, "Final byte write failed: %s\n", strerror(errno));
      fclose(file);
      return;
   }

   if (fflush(file) != 0) {
      fprintf(stderr, "Flush failed: %s\n", strerror(errno));
   }

   fclose(file);
}

void init_device(
   const char * filename,
   bool         is_map_block,
   bool         is_readonly,
   bool         is_nofail,
   bool         is_bypass_fs_check,
   uintmax_t    disk_file_size,
   uintmax_t    block_size) {

   assert(is_map_block == false);

   const char * msg = _("%s is not allowed under ISO C mode.");
   if (is_string_startwith(filename, "UUID=")) {
      print_error(msg, "UUID=");
   } else if (is_string_startwith(filename, "PATH=")) {
      print_error(msg, "PATH=");
   } else if (is_string_startwith(filename, "DEV=")) {
      print_error(msg, "DEV=");
   }

   size_t filename_len = strlen(filename);
   if (filename_len > FILENAME_MAX){
      print_error(_("the <device> is too long. max length is %d bytes"), FILENAME_MAX);
   }

   strncpy(STR_device->name, filename, sizeof(STR_device->name));
   STR_device->is_block = false;
   STR_device->block_count = -1;
   STR_device->block_size = -1;

   if (disk_file_size != 0) {
      create_file(filename, disk_file_size);
   }

   FILE *file;
   if (is_readonly) {
      file = fopen(filename, "rb");
   } else {
      file = fopen(filename, "rb+");
   }
   if (!file) {
      if (is_nofail) {
         windham_exit(0);
      }
      print_error("Cannot open file %s: %s", filename, strerror(errno));
   }

   if (fseek(file, sizeof(Data) - 1, SEEK_SET) != 0) {
      fclose(file);
      print_error("Cannot determine file geometry %s: %s", filename, strerror(errno));
   }

   int c = fgetc(file);
   if (c == EOF) {
      if (feof(file)) {
         fclose(file);
         print_error("File %s is too small to contain Windham disk format.", filename);
      } else {
         fclose(file);
         print_error("Cannot determine file geometry %s: %s", filename, strerror(errno));
      }
   }
   fclose(file);
}
