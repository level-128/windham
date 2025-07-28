#ifndef INCL_MAPPER_
#define INCL_MAPPER_

bool linear_map(const char * device, const char * name, const uint64_t start, const uint64_t size, const char uuid_str[37]);

void map_partition_table(const char * name, bool is_new_map);

int create_crypt_mapping(
   const char * device,
   const char * name,
   const char * enc_type,
   const char password[HASHLEN * 2 + 1],
   char         uuid_str[37],
   size_t       start_sector,
   size_t       end_sector,
   size_t       block_size,
   bool         is_read_only,
   bool         is_allow_discards,
   bool         is_no_read_workqueue,
   bool         is_no_write_workqueue);

void create_crypt_mapping_from_disk_key(
   const char * device,
   const char * target_name,
   const char * enc_type,

   const uint8_t disk_key[HASHLEN],
   uint8_t       uuid[16],

   size_t start_sector,
   size_t end_sector,
   size_t block_size,

   bool read_only,
   bool is_allow_discards,
   bool is_no_read_workqueue,
   bool is_no_write_workqueue,
   bool is_no_map_partition);


// Not implemented under ISO C
enum {
   EMOBJ_try_create_crypt_mapping_OK,
   EMOBJ_try_create_crypt_mapping_FAILED_INIT,
   EMOBJ_try_create_crypt_mapping_FAILED_MAPPING,
};
int try_create_crypt_mapping(const char * file_name, const char * enc_type);

void remove_crypt_mapping(const char * name, bool is_deferred_remove);

void remove_crypt_mapping_by_uuid(const char uuid_str[37]);

void mapper_init();

#if !defined(WINDHAM_ISOC) && defined(IS_FRONTEND_ENTRY)
#include "GNU_Linux/mapper.c"
#else
#include "ISOC/mapper.c"
#endif

#endif