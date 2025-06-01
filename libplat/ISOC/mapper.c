/* cmd interface syntax:
 * cmd string stores within the program. Windham will parse this command per execution,
 * then pass it to system().
 *
 * To modify cmd string, locate this string in the program executable. The method of locating and modifying
 * such string depends on the binary format that your linker produce: e.g, for ELF format, such string may reside
 * under .rodata section. As for PE, bFLT, Mach-O, WASM or a.out, similar method exists. Search for string:
 * "MAPPER_BACKEND_OPEN:\xff", your cmd command should appear after this prefix, with \x03 as terminator.
 *
 * Use "\xff_" as format specifiers. Each format represents different variables:
 * \xffa: device path
 * \xffs: device mount name
 * \xffd: enc_type
 * \xfff: password (base_64)
 * \xffg: uuid string
 * \xffh: start sector
 * \xffj: end sector
 * \xffk: block size
*/

#define MAPPER_BACKEND_OPEN_STRING  "MAPPER_BACKEND_OPEN:\xff"


volatile const char mapper_backend_open_cmd[256] =
    MAPPER_BACKEND_OPEN_STRING;

char* format_string(const char* fmt, const char* arr[8]) {
   size_t total_len = 0;
   const char* p = fmt;

   while (*p) {
      if (*p == '\xff') {
         const char c = *(p + 1);
         int index = 0;
         switch (c) {
         case 'a': index = 0; break;
         case 's': index = 1; break;
         case 'd': index = 2; break;
         case 'f': index = 3; break;
         case 'g': index = 4; break;
         case 'h': index = 5; break;
         case 'j': index = 6; break;
         case 'k': index = 7; break;
         default:
            print_error(_("unknown format specifier :\"\\xff%c\""), c);
         }
         total_len += strlen(arr[index]);
         p += 2;
      } else {
         total_len++;
         p++;
      }
   }

   char* buf = malloc(total_len + 1);
   if (!buf) {
      perror("malloc");
   }

   char* dest = buf;
   p = fmt;
   while (*p) {
      if (*p == '\xff') {
         const char c = *(p + 1);
         int index = 0;
         switch (c) {
         case 'a': index = 0; break;
         case 's': index = 1; break;
         case 'd': index = 2; break;
         case 'f': index = 3; break;
         case 'g': index = 4; break;
         case 'h': index = 5; break;
         case 'j': index = 6; break;
         case 'k': index = 7; break;
         default:
            print_error(_("unknown format specifier :\"\\xff%c\""), c);
         }
         const char* sub = arr[index];
         size_t sub_len = strlen(sub);
         memcpy(dest, sub, sub_len);
         dest += sub_len;
         p += 2;
      } else {
         *dest++ = *p++;
      }
   }
   *dest = '\0';

   return buf;
}

char * parse_cmd(
   const char * device,
   const char * name,
   const char * enc_type,
   const char   password[HASHLEN * 2 + 1],
   char         uuid_str[37],
   size_t       start_sector,
   size_t       end_sector,
   size_t       block_size) {
   char * cmdend = strstr((const char *) mapper_backend_open_cmd, "\x03");
   if (cmdend == NULL) {
      return NULL;
   }

   char * cmdstart = strstr((const char *) mapper_backend_open_cmd, MAPPER_BACKEND_OPEN_STRING);
   if (cmdstart == NULL || cmdstart >= cmdend) {
      print_warning(_("cmd string in binary has been modified and cannot be recognized."));
      return NULL;
   }
   cmdstart += strlen(MAPPER_BACKEND_OPEN_STRING);
   uintptr_t cmdlen = (uintptr_t)cmdend - (uintptr_t)cmdstart;

   char * fmt = malloc(cmdlen + 1);

   memcpy(fmt, cmdstart, cmdlen);
   fmt[cmdlen] = 0;

   char * start_sector_str = malloc(snprintf(NULL, 0, "%zu", start_sector) + 1);
   sprintf(start_sector_str, "%zu", start_sector);
   char * end_sector_str = malloc(snprintf(NULL, 0, "%zu", end_sector) + 1);
   sprintf(end_sector_str, "%zu", end_sector);
   char * block_size_str = malloc(snprintf(NULL, 0, "%zu", block_size) + 1);
   sprintf(block_size_str, "%zu", block_size);
   const char * arr[8] = {device, name, enc_type, password, uuid_str, start_sector_str, end_sector_str, block_size_str};

   char * formatted_cmd_string = format_string(fmt, arr);
   free(fmt);
   free(start_sector_str);
   free(end_sector_str);
   free(block_size_str);

   return formatted_cmd_string;
}



bool linear_map(const char * device, const char * name, const uint64_t start, const uint64_t size, const char uuid_str[37]) {
  print_warning(_("cannot map partition %s according to the detected partition table on device. "
                  "Not available under ISO C mode."), device);
  return false;
}


void remove_crypt_mapping_by_uuid(const char uuid_str[37]) {
  print_warning(_("Cannot remove device. Not available under ISO C mode."));
}


void map_partition_table(const char * name, bool is_new_map) {

  print_warning(_("Cannot map device. Not available under ISO C mode."));
}


void remove_crypt_mapping(const char * name, bool is_deferred_remove) {

  print_warning(_("Cannot remove device. Not available under ISO C mode."));
}



int create_crypt_mapping(
   const char * device,
   const char * name,
   const char * enc_type,
   const char   password[HASHLEN * 2 + 1],
   char         uuid_str[37],
   size_t       start_sector,
   size_t       end_sector,
   size_t       block_size,
   bool         is_read_only,
   bool         is_allow_discards,
   bool         is_no_read_workqueue,
   bool         is_no_write_workqueue) {

   if (is_has_system_env) {
      char * cmd = parse_cmd(device, name, enc_type, password, uuid_str, start_sector, end_sector, block_size);
      if (cmd == NULL) {
         printf(_("Cannot map device %s to %s. device mapper backend is not available under ISO C mode, and command string"
                " not set.\n"), device, name);
      } else {
         int cmdret = system(cmd);
         free(cmd);
         printf(_("mapper cmd returns with return code %i\n"), cmdret);
         return 0;
      }
   } else {
      printf(_("Execution environment does not contain command processor. "));
   }

  printf("To view encryption information, press enter:");
  if (getchar() == '\n') {
    printf("\n");
     printf(_("map device %s with key: %s\n"), device, password);
    printf(_("additional parameters:\n"
             "name = %s\n"
             "enc_type = %s\n"
             "password = %s\n"
             "sector range = (%zu, %zu)\n"
             "block size = %zu\n"
             "is_read_only = %d\n"
             "is_allow_discards = %d\n"
             "is_no_read_workqueue = %d\n"
             "is_no_write_workqueue = %d\n"),
             name, enc_type, uuid_str, start_sector, end_sector, block_size,
             is_read_only,is_allow_discards,is_no_read_workqueue,is_no_write_workqueue);
  }
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

   if (! is_no_map_partition) {
      map_partition_table(target_name, true);
   }
}


void mapper_init() {
      is_device_mapper_available = false;
}


