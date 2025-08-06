//
// Created by level-128 on 8/28/23.
//

#ifndef INCL_MAPPER
#define INCL_MAPPER

#ifndef WINDHAM_ISOC

#include <libdevmapper.h>
#include <sys/utsname.h>
#include <dlfcn.h>

#endif



#include "srclib.c"
#include "endian.c"

// data

struct dm_task * (*p_dm_task_create)(int type);

int (*p_dm_task_set_name)(struct dm_task * dmt, const char * name);

int (*p_dm_task_set_ro)(struct dm_task * dmt);

int (*p_dm_task_set_uuid)(struct dm_task * dmt, const char * uuid);

int (*p_dm_task_run)(struct dm_task * dmt);

void (*p_dm_task_destroy)(struct dm_task * dmt);

int (*p_dm_task_add_target)(
   struct dm_task * dmt,
   uint64_t         start,
   uint64_t         size,
   const char *     ttype,
   const char *     params);

void (*p_dm_task_update_nodes)(void);

int (*p_dm_task_deferred_remove)(struct dm_task * dmt);


bool is_device_mapper_available;

#define GPT_HDR_REVISION 0x00010000

typedef struct {
   alignas(1) uint8_t  hdr_sig[8];
   alignas(4) uint32_t hdr_revision;
   alignas(4) uint32_t hdr_size;
   alignas(4) uint32_t hdr_crc_self;
   alignas(4) uint32_t hdr_reserved;
   alignas(8) uint64_t hdr_lba_self;
   alignas(8) uint64_t hdr_lba_alt;
   alignas(8) uint64_t hdr_lba_start;
   alignas(8) uint64_t hdr_lba_end;
   alignas(1) uint8_t  hdr_uuid[16];
   alignas(8) uint64_t hdr_lba_table;
   alignas(4) uint32_t hdr_entries;
   alignas(4) uint32_t hdr_entsz;
   alignas(4) uint32_t hdr_crc_table;

   alignas(1) uint8_t padding[420]; // offset: 92
} gpt_hdr;


typedef struct {
   alignas(1) uint8_t  ent_type[16];
   alignas(1) uint8_t  ent_uuid[16];
   alignas(8) uint64_t ent_lba_start;
   alignas(8) uint64_t ent_lba_end;
   alignas(8) uint64_t ent_attr;
   alignas(2) uint16_t ent_name[36]; // UTF-16. offset: 56
} gpt_ent;


int entries_qsort_comp_func(const void * restrict x, const void * restrict y) {
   // x and y are small endian ints.
   const gpt_ent * restrict ent1 = x;
   const gpt_ent * restrict ent2 = y;
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


bool read_GPT_header(
   const char * WINDHAM_ATTRIBUTE(maybe_unused)            device,
   Read_GPT_header_return * WINDHAM_ATTRIBUTE(maybe_unused) return_) {

   gpt_hdr hdr;
   FILE *  fd = fopen(device, "rb");

   if (fd == NULL) {
      print_error(_("failed to detect GPT header on device %s"), device);
   }
   fseek(fd, 512, SEEK_SET); // skip protective MBR

   if (fread(&hdr, 1, sizeof(gpt_hdr), fd) != sizeof(gpt_hdr)) {
      print_warning(_("Failed to detect GPT header on device %s"), device);
   }

   if (memcmp(hdr.hdr_sig, (uint8_t[]){69, 70, 73, 32, 80, 65, 82, 84}, sizeof(hdr.hdr_sig))) {
      fclose(fd);
      return false; // not GPT
   }

   if (memcmp((uint8_t[sizeof(hdr.padding)]){0}, hdr.padding, sizeof(hdr.padding)) != 0 || hdr.hdr_reserved != 0) {
      print_warning(_("invalid GPT header detected on device %s"), device);
      fclose(fd);
      return false;
   }

   fseek(fd, hdr.hdr_lba_table * 512, SEEK_SET); // move to lba table
   gpt_ent * gpt_ent_array = malloc(hdr.hdr_entries * hdr.hdr_entsz);

   if (fread(gpt_ent_array, 1, hdr.hdr_entries * hdr.hdr_entsz, fd) != hdr.hdr_entries * hdr.hdr_entsz) {
      perror("read");
   }

   qsort(gpt_ent_array, hdr.hdr_entries, hdr.hdr_entsz, entries_qsort_comp_func);

   return_->last_part.ent_lba_end   = le64toh(gpt_ent_array->ent_lba_end);
   return_->last_part.ent_lba_start = le64toh(gpt_ent_array->ent_lba_start);
   return_->last_part.ent_attr      = gpt_ent_array->ent_attr;
   memcpy(return_->last_part.ent_uuid, gpt_ent_array->ent_uuid, 16);

   memcpy(&return_->uuid, hdr.hdr_uuid, sizeof(hdr.hdr_uuid));
   free(gpt_ent_array);

   return_->lba_end     = le64toh(hdr.hdr_lba_end);
   return_->lba_padding = return_->lba_end - return_->last_part.ent_lba_end;

   fclose(fd);
   return true;
}


void convert_disk_key_to_hex_format(const uint8_t master_key[32], char key[HASHLEN * 2 + 1]) {
   const char * hex_chars = "0123456789abcdef";

   for (size_t i = 0; i < HASHLEN; ++i) {
      uint8_t byte   = master_key[i];
      key[i * 2]     = hex_chars[(byte >> 4) & 0xF];
      key[i * 2 + 1] = hex_chars[byte & 0xF];
   }

   key[HASHLEN * 2] = '\0'; // Null-terminate the string
}
#include "../libplat/mapper.c"
#endif

