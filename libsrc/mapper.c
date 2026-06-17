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
#define GPT_ENTRIES_MIN   1
#define GPT_ENTRIES_MAX   65536
#define GPT_ENTSZ_MIN     128
#define GPT_ENTSZ_MAX     512
#define GPT_HEADER_SIZE   92
#define GPT_MBR_TYPE_EE   0xEE


/* ── CRC32 (UEFI 2.10 uses standard CRC-32/MPEG-2, poly 0xEDB88320) ── */

static uint32_t crc32_table[256];
static bool     crc32_table_init = false;

static void crc32_init(void) {
    if (crc32_table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (c >> 1) ^ 0xEDB88320UL : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_init = true;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    crc32_init();
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFFUL;
}


/* ── Protective MBR: LBA 0 must contain a type-0xEE partition ── */

static bool check_protective_mbr(FILE *fd) {
    uint8_t mbr[512];
    long    save = ftell(fd);

    fseek(fd, 0, SEEK_SET);
    if (fread(mbr, 1, 512, fd) != 512) {
        fseek(fd, save, SEEK_SET);
        return false;
    }
    fseek(fd, save, SEEK_SET);

    if (mbr[510] != 0x55 || mbr[511] != 0xAA) return false;

    for (int i = 0; i < 4; i++) {
        if (mbr[446 + i * 16 + 4] == GPT_MBR_TYPE_EE) return true;
    }
    return false;
}

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

   /* Protective MBR */
   if (!check_protective_mbr(fd)) {
      fclose(fd);
      return false;
   }

   /* Read GPT header at LBA 1 */
   fseek(fd, 512, SEEK_SET);

   size_t hdr_read_size = sizeof(gpt_hdr);
   if (fread(&hdr, 1, hdr_read_size, fd) != hdr_read_size) {
      print_warning(_("Failed to read GPT header on device %s"), device);
      fclose(fd);
      return false;
   }

   /* Signature */
   if (memcmp(hdr.hdr_sig, (uint8_t[]){69, 70, 73, 32, 80, 65, 82, 84}, sizeof(hdr.hdr_sig))) {
      fclose(fd);
      return false;
   }

   /* Validate header size (spec minimum 92; future versions may be larger) */
   uint32_t header_size = le32toh(hdr.hdr_size);
   if (header_size < GPT_HEADER_SIZE || header_size > sizeof(gpt_hdr)) {
      print_warning(_("Unsupported GPT header size %u on device %s"), header_size, device);
      fclose(fd);
      return false;
   }

   /* Revision */
   uint32_t revision = le32toh(hdr.hdr_revision);
   if (revision < GPT_HDR_REVISION) {
      print_warning(_("Unsupported GPT revision 0x%x on device %s"), revision, device);
      fclose(fd);
      return false;
   }

   /* Reserved fields */
   if (hdr.hdr_reserved != 0 ||
       memcmp((uint8_t[sizeof(hdr.padding)]){0}, hdr.padding, sizeof(hdr.padding)) != 0) {
      print_warning(_("Invalid GPT header (non-zero reserved fields) on device %s"), device);
      fclose(fd);
      return false;
   }

   /* Header CRC32 (zero out the CRC field for computation) */
   uint32_t stored_crc = le32toh(hdr.hdr_crc_self);
   uint32_t saved_crc  = hdr.hdr_crc_self;
   hdr.hdr_crc_self = 0;
   uint32_t computed_crc = crc32_compute((uint8_t *)&hdr, header_size);
   hdr.hdr_crc_self = saved_crc;
   if (stored_crc != computed_crc) {
      print_warning(_("GPT header CRC32 mismatch on device %s"), device);
      fclose(fd);
      return false;
   }

   /* Bounds on partition entry array */
   uint32_t entries = le32toh(hdr.hdr_entries);
   uint32_t entsz   = le32toh(hdr.hdr_entsz);
   if (entries < GPT_ENTRIES_MIN || entries > GPT_ENTRIES_MAX) {
      print_warning(_("Invalid GPT entry count %u on device %s"), entries, device);
      fclose(fd);
      return false;
   }
   if (entsz < GPT_ENTSZ_MIN || entsz > GPT_ENTSZ_MAX) {
      print_warning(_("Invalid GPT entry size %u on device %s"), entsz, device);
      fclose(fd);
      return false;
   }
   if (entsz < sizeof(gpt_ent)) {
      print_warning(_("GPT entry size %u smaller than expected %zu on device %s"),
                    entsz, sizeof(gpt_ent), device);
      fclose(fd);
      return false;
   }

   /* Read partition entry array */
   size_t table_bytes = (size_t)entries * entsz;
   fseek(fd, le64toh(hdr.hdr_lba_table) * 512, SEEK_SET);
   gpt_ent *gpt_ent_array = malloc(table_bytes);
   if (!gpt_ent_array) {
      print_error(_("Out of memory reading GPT partition table on %s"), device);
   }
   if (fread(gpt_ent_array, 1, table_bytes, fd) != table_bytes) {
      print_warning(_("Failed to read GPT partition table on device %s"), device);
      free(gpt_ent_array);
      fclose(fd);
      return false;
   }

   /* Partition table CRC32 */
   uint32_t table_crc_stored = le32toh(hdr.hdr_crc_table);
   uint32_t table_crc_comp   = crc32_compute((uint8_t *)gpt_ent_array, table_bytes);
   if (table_crc_stored != table_crc_comp) {
      print_warning(_("GPT partition table CRC32 mismatch on device %s"), device);
      free(gpt_ent_array);
      fclose(fd);
      return false;
   }

   qsort(gpt_ent_array, entries, entsz, entries_qsort_comp_func);

   return_->last_part.ent_lba_end   = le64toh(gpt_ent_array->ent_lba_end);
   return_->last_part.ent_lba_start = le64toh(gpt_ent_array->ent_lba_start);
   return_->last_part.ent_attr      = gpt_ent_array->ent_attr;
   memcpy(return_->last_part.ent_uuid, gpt_ent_array->ent_uuid, 16);

   memcpy(&return_->uuid, hdr.hdr_uuid, sizeof(hdr.hdr_uuid));
   free(gpt_ent_array);

   return_->lba_end = le64toh(hdr.hdr_lba_end);
   uint64_t last_lba = return_->last_part.ent_lba_end;
   return_->lba_padding = (last_lba < return_->lba_end)
                            ? return_->lba_end - last_lba
                            : 0;

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

