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

uint64_t isoc_get_file_size(FILE *stream){
   fpos_t stored_pos;
   if (fgetpos(stream, &stored_pos)){
      perror("fgetpos");
      exit(1);
   }
   if (fseek(stream, 0, SEEK_END)){
      print_error(_("Cannot determine geometry: %s, your platform does not allow fseek + SEEK_END on this device/file."
                    " This happens under some platforms that does not allow fseek to act on disks or block devices."), strerror(errno));
      exit(1);
   }

	uint64_t sum_res = 0;
	if (sizeof(uint64_t) != sizeof(long)){
		while (fseek(stream, LONG_MIN, SEEK_CUR) == 0){
			sum_res -= LONG_MIN;
		}
	}

   long int res = ftell(stream);
   if (res == -1L){
      perror("cannot get file size");
      exit(1);
   }
   sum_res += res;
   if (fsetpos(stream, &stored_pos)){
      perror("fsetpos");
      exit(1);
   }
   return sum_res;
}

void init_device(
   const char * filename,
   bool         is_map_block,
   bool         is_readonly,
   bool         is_nofail,
   bool         is_bypass_fs_check,
   uintmax_t    disk_file_size,
   uintmax_t    block_size) {


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
	if (is_map_block) {
		STR_device->block_size  = DEFAULT_BLOCK_SIZE;
		STR_device->block_count = isoc_get_file_size(file) / DEFAULT_BLOCK_SIZE * (DEFAULT_BLOCK_SIZE / 512);
		if (STR_device->block_count < RAW_HEADER_AREA_IN_SECTOR) {
			print_error("File %s is too small to contain Windham disk format, double check your file.", filename);
		}
	} else {
		// Still get file size so end_sector can be computed correctly
		STR_device->block_size  = DEFAULT_BLOCK_SIZE;
		uint64_t fsize = isoc_get_file_size(file);
		if (fsize > 0) {
			STR_device->block_count = (int64_t)(fsize / DEFAULT_BLOCK_SIZE * (DEFAULT_BLOCK_SIZE / 512));
		} else {
			STR_device->block_count = -1;
		}
	}
   fclose(file);
}
