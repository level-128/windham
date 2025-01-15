#pragma once

#include <stdint.h>
#include "../library_intrnlsrc/enclib.c"
#include "../library_intrnlsrc/kerkey.c"
#include "../library_intrnlsrc/libloop.c"
#include "../library_intrnlsrc/mapper.c"


#define OPERATION_BACKEND_UNENCRYPT_HEADER                \
    int ret_key_zone, ret_level; \
    uint16_t ret_key_location;\
         get_master_key(data, master_key, key, device, max_unlock_mem, max_unlock_time, max_unlock_level, is_allow_nolock, \
&ret_level, &ret_key_zone, &ret_key_location);                               \
\
   if (!unlock_metadata_using_master_key(&data, master_key)){ \
     print_error(_("The header is likely damaged, which means you can't unlock your device even using your masterkey. Sorry, there is nothing that I could do...")); \
      }


#define OPERATION_LOCK_AND_WRITE                                                                                                           \
   lock_metadata_using_master_key(&data, master_key);                                                                                      \
   write_header_to_device(&data, device, offset);


#define PARAMS_FOR_KEY Key key, uint8_t master_key[32], uint64_t max_unlock_mem, double max_unlock_time, int max_unlock_level, \
   const bool    is_allow_nolock,    const bool is_decoy


// supported crypt
char * crypt_list[]     = {"aes", "twofish", "serpent", NULL};
char * chainmode_list[] = {"cbc", "xts", "ecb", NULL};
char * iv_list[]        = {"plain64", "plain64be", "essiv", "eboiv", NULL};


void operate_header_on_device(Data * data, const char * device, int64_t offset, bool is_read) {
   ssize_t result;
   assert(offset % 4 == 0);
   const int fp = open(
      device,
      O_DSYNC | (is_read
                    ? O_RDONLY
                    : O_WRONLY));
   if (fp == 0) {
      print_error(_("Failed to open %s: %s"), device, strerror(errno));
   }

   if (offset < 0) {
      lseek(fp, offset, SEEK_END);
   } else {
      lseek(fp, offset, SEEK_SET);
   }

   if (is_read) {
      result = read(fp, data, sizeof(Data));
      if (result != sizeof(Data)) {
         print_error(_("Failed to read %s: %s\""), device, strerror(errno));
      }
   } else {
      result = write(fp, data, sizeof(Data));
      if (result != sizeof(Data)) {
         print_error(_("Failed to write %s: %s\""), device, strerror(errno));
      }
   }
   close(fp);
}


void write_header_to_device(const Data * data, const char * device, const int64_t offset) {
   operate_header_on_device((Data *) data, device, offset, false);
}

void get_header_from_device(Data * data, const char * device, const int64_t offset) {
   operate_header_on_device(data, device, offset, true);
}

struct SystemInfo {
   unsigned long free_ram;
   unsigned long free_swap;
   unsigned long total_ram;
};


struct SystemInfo sys_info;


void get_system_info() {
#ifdef WINDHAM_USE_NULL_MALLOC
   sys_info.free_ram  = ULONG_MAX;
   sys_info.free_swap = ULONG_MAX;
#else
   FILE * meminfo = fopen("/proc/meminfo", "r");
   if (meminfo == NULL) {
      print_warning(
         _("Failed to read system information. Can not determine adequate memory size (or memory limit) for key derivation."));
      sys_info.free_ram  = ULONG_MAX;
      sys_info.free_swap = ULONG_MAX;
      return;
   }

   char          line[256];
   unsigned long memFree  = 0;
   unsigned long memTotal = 0;
   unsigned long cached   = 0;
   unsigned long swapFree = 0;

   while (fgets(line, sizeof(line), meminfo)) {
      if (strncmp(line, "MemFree:", 8) == 0) {
         sscanf(line, "%*s %lu", &memFree);
      } else if (strncmp(line, "MemTotal:", 9) == 0) {
         sscanf(line, "%*s %lu", &memTotal);
      } else if (strncmp(line, "Cached:", 7) == 0) {
         sscanf(line, "%*s %lu", &cached);
      } else if (strncmp(line, "SwapFree:", 9) == 0) {
         sscanf(line, "%*s %lu", &swapFree);
      }
   }

   sys_info.free_ram  = memFree + cached;
   sys_info.free_swap = swapFree;
   sys_info.total_ram = memTotal;

   fclose(meminfo);
#endif
}


size_t check_target_mem(size_t target_mem, bool is_encrypt, bool is_allow_swap) {
   if (target_mem == SIZE_MAX) { // no memory designated
      if ((double) sys_info.free_ram / (double) sys_info.total_ram < 0.3 && ! is_allow_swap) {
         print_warning(
            _("The system is low on memory (< 30%%). It is recommended to utilize the system swap space via parameter "
               "\"--allow-swap\". However, as for windham, swap deduces security."));
      }
      if (is_encrypt) {
         return (size_t) (sys_info.total_ram * 0.01 * DEFAULT_DISK_ENC_MEM_RATIO_CAP); // 30% default
      }
      return SIZE_MAX;
   }

   if (sys_info.free_ram < target_mem) {
      if ((sys_info.free_swap + sys_info.free_ram) > target_mem) {
         print_warning(_("The designated ram might cause other programs to swap."));
      } else {
         size_t new_target_mem = sys_info.free_swap + sys_info.free_ram - (1 << 16);
         if (is_encrypt) {
            ask_for_conformation(
               _(
                  "The RAM and swap are not enough form the designated RAM. Adjusted the max RAM "
                  "consumption for Key derivation from %lu (KiB) to %lu (KiB). This may degrade security, continue?"),
               target_mem,
               new_target_mem);
         } else {
            print_warning(
               _("Adjusted the requested max RAM consumption from %lu (KiB) to %lu (KiB) because of insufficient memory. "
                  "If your computer has less available memory than the computer that creates the encryption target, you may not "
                  "successfully decrypt this target. Consider adding more "
                  "swap spaces as a workaround."),
               target_mem,
               new_target_mem);
         }
         return new_target_mem;
      }
   }
   return target_mem;
}


typedef enum {
   NMOBJ_MAPPER_DEVSTAT_DECOY,
   NMOBJ_MAPPER_DEVSTAT_SUSP,
   NMOBJ_MAPPER_DEVSTAT_NORM
} ENUM_MAPPER_DEVSTAT;


ENUM_MAPPER_DEVSTAT detect_device_status(const char * device, bool is_decoy) {
   if (is_decoy) {
      return NMOBJ_MAPPER_DEVSTAT_DECOY;
   }
  
   uint8_t   content_head[16];
   const int fp = open(device, O_RDONLY);
   if (fp == 0) {
      print_error(_("can not open device %s"), device);
   }

   if (read(fp, content_head, sizeof(content_head)) != sizeof(content_head)) {
     perror("read");
   }
   close(fp);

   if (memcmp(content_head, head, sizeof(head)) == 0) {
      return NMOBJ_MAPPER_DEVSTAT_SUSP;
   }

   return NMOBJ_MAPPER_DEVSTAT_NORM;
}


ENUM_MAPPER_DEVSTAT locate_possible_header_location_and_type(
   const char * device,
   Data *       return_data,
   int64_t *    return_offset,
   const bool   is_decoy) {
   const ENUM_MAPPER_DEVSTAT ret = detect_device_status(device, is_decoy);
   switch (ret) {
   case NMOBJ_MAPPER_DEVSTAT_SUSP:

   /* fall through */
   case NMOBJ_MAPPER_DEVSTAT_NORM:
      *return_offset = 0;
      break;
   case NMOBJ_MAPPER_DEVSTAT_DECOY:
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
         print_error(_("decoy partition feature for big endian devices is currently missing."));
#endif
      print_warning(_("Unlocking %s assuming decoy partition exits"), device);
      Read_GPT_header_return gpt_header_ret;
      if (read_GPT_header(device, &gpt_header_ret) == false) {
         *return_offset = -HEADER_AREA_IN_SECTOR;
      } else {
         *return_offset = (gpt_header_ret.lba_end + 1 - HEADER_AREA_IN_SECTOR) * 512;
         printf(_("GPT partition table detected, locating metadata by GPT genometry.\n"));
      }
      break;
   }
   get_header_from_device(return_data, device, *return_offset);
   return ret;
}


int64_t get_new_header_range_and_offset_based_on_size(
   const char * device,
   uint64_t     device_block_count,
   size_t *     start_sector,
   size_t *     end_sector,
   size_t       block_size,
   uint64_t     decoy_size) {
   long long safe_node = (1 << 24) / 512; // safe sector

   int64_t return_val;
   
      if (device_block_count < (8 << 10) / 512) {
         print_error(_("Device %s is too small; Windham requires at least %i KiB."), device, 8);
      }
      if ((int) block_size != STR_device->block_size && STR_device->block_size != 1) {
         print_warning(
            _("The device has blocksize of %i bytes, while Windham has been configured to use %zu bytes. This may decrease "
               "performance. Use \"--block-size=%i\" when create to designate a hardware-matched block size."),
            STR_device->block_size,
            block_size,
            STR_device->block_size);
      }


   
      if (decoy_size != 0) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	print_error(_("decoy partition feature for big endian devices is currently missing."));
#endif
	decoy_size /= 512; // decoy size is in bytes;
	if (decoy_size % (block_size / 512) != 0){
	  print_warning(_("decoy size does not align with block size, auto shrinking decoy size to match."));
	  decoy_size = decoy_size / (block_size / 512) * (block_size / 512);
      }

      Read_GPT_header_return gpt_header_ret;
      if (read_GPT_header(device, &gpt_header_ret) == false) {
         printf(
            _(
               "Decoy device does not contain GPT header. Solver has nothing to do. Placing the header at the last %ld logical "
               "sectores.\n"),
            HEADER_AREA_IN_SECTOR);
         long long lendiff = device_block_count
                             /* lba_end is the last useable block, not the border, so + 1. */
                             - (decoy_size + HEADER_AREA_IN_SECTOR);
         if (lendiff <= safe_node) {
            print_error(
               _("The size of the device is too small to deploy decoy partition. Extra %lli sectors are required."),
               safe_node);
         }

         *end_sector   = (device_block_count - HEADER_AREA_IN_SECTOR) / (block_size / 512) * (block_size / 512) - 1;
	 *start_sector = *end_sector - decoy_size;

         return_val = -HEADER_AREA_IN_SECTOR * 512;
      } else {
         device_block_count = (gpt_header_ret.lba_end + 1) - gpt_header_ret.last_part.ent_lba_start;
         long long lendiff  = device_block_count - (decoy_size + HEADER_AREA_IN_SECTOR);
         if (lendiff <= safe_node) {
            print_error(
               _("The size of the last partition is too small to deploy decoy partition. Extra %lli sectors are required."),
               safe_node);
         }

         *end_sector = (gpt_header_ret.lba_end + 1) // means device block count
	   / (block_size / 512) * (block_size / 512) - 1 - HEADER_AREA_IN_SECTOR;

	 *start_sector = *end_sector - decoy_size;

         uint8_t * uuid  = gpt_header_ret.uuid;
         uint8_t * uuid1 = gpt_header_ret.last_part.ent_uuid;

         printf(
            _(
               "decoy partition Layout Format:\n"
               "\tUUID of the GPT device: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"
               "\tUUID of the last available GPT partition: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"
               "\tlogical block range of the last GPT partition: %lu - %lu (inclusive)\n"
               "\tLast available GPT sector (LBA end, inclusive): %lu\n"
               "\twindham partition start sector: %lu\n"
               "\twindham partition end sector: %lu\n"
               "\tTotal usable size: %lu\n"
               "\tMetadata block storage sector location: %lu\n\n"),
            uuid[0],
            uuid[1],
            uuid[2],
            uuid[3],
            uuid[4],
            uuid[5],
            uuid[6],
            uuid[7],
            uuid[8],
            uuid[9],
            uuid[10],
            uuid[11],
            uuid[12],
            uuid[13],
            uuid[14],
            uuid[15],
            uuid1[0],
            uuid1[1],
            uuid1[2],
            uuid1[3],
            uuid1[4],
            uuid1[5],
            uuid1[6],
            uuid1[7],
            uuid1[8],
            uuid1[9],
            uuid1[10],
            uuid1[11],
            uuid1[12],
            uuid1[13],
            uuid1[14],
            uuid1[15],
            gpt_header_ret.last_part.ent_lba_start,
            gpt_header_ret.last_part.ent_lba_end,
            gpt_header_ret.lba_end,
            *start_sector,
            *end_sector,
            *end_sector - *start_sector,
            (gpt_header_ret.lba_end + 1) - HEADER_AREA_IN_SECTOR);
         return_val = (gpt_header_ret.lba_end + 1 - HEADER_AREA_IN_SECTOR) * 512;
      }
   } else {
      *start_sector = WINDHAM_FIRST_USEABLE_LGA;
      *end_sector   = device_block_count - device_block_count % (block_size / 512);
      return_val = 0;
   }
   return return_val;
}
