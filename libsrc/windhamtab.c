#include "srclib.c"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_OPTIONS 30
/* #define FILENAME "/etc/windhamtab" */


#define WINDHAMTABMSG                                                                                                                      \
   "# /etc/windhamtab: Windham device information.\n"                                                                                      \
   "#\n"                                                                                                                                   \
   "# Use 'lsblk -o NAME,PARTUUID' to print the universally unique identifier for all\n"                                                   \
   "# devices; this may be used with UUID= as a more robust way to name devices that\n"                                                    \
   "# works even if disks are added and removed.\n"                                                                                        \
   "#\n"                                                                                                                                   \
   "# Windham will read /etc/windhamtab when using 'windham Open TAB'\n"                                                                   \
   "#\n"                                                                                                                                   \
   "# Avaliable options are: \n"                                                                                                           \
   "# \"readonly\" \"no-read-workqueue\" \"no-write-workqueue\" \"nofail\"\n"                                                              \
   "# \"allow-discards\" \"systemd\" \"no-map-partition\" \"max-unlock-memory=<int>\"\n"                                                   \
   "# \"max-unlock-time=<float>\" \"unlock-slot=<int>\"\n"                                                                                 \
   "# \n"                                                                                                                                  \
   "# If no option is needed, use the placeholder \"none\". To view help for each option,\n"                                              \
   "# use \"windham Open --help\".\n"                                                                                                      \
   "#\n"                                                                                                                                   \
   "# Syntax: \n"                                                                                                                          \
   "# <device: PATH= | UUID= | DEV= >  <to:>  <key: ASK | KEYFILE= | CLEVIS= >  <options:>  <pass>\n"                                      \
   "#\n"                                                                                                                                   \
   "# Example: \n"                                                                                                                         \
   "# DEV=/dev/sdb1  encsdb1  ASK  systemd,readonly  1\n"                                                                    \
   "# UUID=2f7d1c8c-7955-45cb-8b66-4071c34b1fcb  windham_home  KEYFILE=/home/keyfile none 2\n\n"

enum {
   NMOBJ_windhamtab_ro,
   NMOBJ_windhamtab_no_read_wq,
   NMOBJ_windhamtab_no_write_wq,
   NMOBJ_windhamtab_nofail,
   NMOBJ_windhamtab_systemd,
   NMOBJ_windhamtab_max_unlock_mem,
   NMOBJ_windhamtab_max_unlock_time,
   NMOBJ_windhamtab_target_allow_discards,
   NMOBJ_windhamtab_is_no_map_partition,
   NMOBJ_windhamtab_COUNT
};

typedef struct {
   char          *device;
   char          *to;
   char          *key;
   unsigned short pass;
   unsigned int   option_flags : NMOBJ_windhamtab_COUNT;
   size_t         max_unlock_mem;
   double         max_unlock_time;
   int            unlock_slot;

} WindhamtabEntity;

int entiry_comp(const WindhamtabEntity *a, const WindhamtabEntity *b) {
   if (a->pass == b->pass) {
     return 0;}
   return a->pass < b->pass ? -1: 1;
}


bool starts_with(const char *str, const char *prefix) {
   return strncmp(str, prefix, strlen(prefix)) == 0;
}

char *get_next_token(char **str) {
   while (**str == ' ')
      (*str)++;
   if (**str == 0 || **str == '\n') {
      if (**str == '\n') {
         (*str)++;
      }
      return NULL;
   }
   char *token = *str;
   int   len   = 0;
   while (*(*str + len) != '\0' && *(*str + len) != ' ' && *(*str + len) != '\n')
      len++;
   char *result = malloc(len + 1);
   memcpy(result, token, len);
   result[len] = '\x00';
   (*str) += len;
   return result;
}

char *parse_line(char *line, WindhamtabEntity *entity, bool *is_content, int lineno) {
   // TODO: line support
   char *return_;
   *is_content = true;

   for (; *line == ' '; line++)
      ;
   if (line[0] == '#') {
      for (; !(*line == 0 || *line == '\n'); line++)
         ;
      *is_content = false;
      return line + 1; // Skip comments and empty lines
   }
   if (line[0] == '\n') {
      *is_content = false;
      return line + 1;
   }
   if (line[0] == '\0') {
      *is_content = false;
      return NULL;
   }

   // Split line into tokens
   char *cursor = line;

   char *token = get_next_token(&cursor);
   if (!token) {
      print_error(_("invalid syntax at line %i. Device field must be <PATH= | UUID= | DEV= >"), lineno);
   }
   entity->device = token;

   token = get_next_token(&cursor);
   if (!token) {
      print_error(_("invalid syntax at line %i. <to> field must be a valid string"), lineno);
   }
   entity->to = token;

   token = get_next_token(&cursor);
   if (!token) {
      print_error(_("invalid syntax at line %i. Key field must be <key: ASK | KEYFILE= | CLEVIS= >"), lineno);
   }
   entity->key = token;

   token = get_next_token(&cursor);
   if (!token) {
      print_error(_("invalid syntax at line %i. Option field must be a valid options seperated by comma."), lineno);
   }
   char *option_str = token;

   token = get_next_token(&cursor);
   if (!token) {
      print_error(_("invalid syntax at line %i. Pass must be a valid integer."), lineno);
   }
   if (get_next_token(&cursor) == NULL) {
      return_ = cursor;
   } else {
      print_error(_("invalid syntax at line %i, after token \"%.10s\". Extra token at line. "), lineno, token);
      exit(1);
   }

   char *endptr;
   errno = 0;

   unsigned long value = strtoul(token, &endptr, 10);
   if (errno == ERANGE || value > USHRT_MAX) {
      print_error(_("Value out of range for unsigned short: %s, at line %i\n"), token, lineno);
   }
   if (endptr == token) {
      // No digits were found
      print_error(_("No digits were found: %s, at line %i\n"), token, lineno);
   }
   if (*endptr != '\0') {
      // Further characters after the number
      print_error(_("Additional characters found after: %s, at line %i\n"), token, lineno);
   }
   free(token);
   entity->pass = (unsigned short) value;

   // Validate device
   if (!(starts_with(entity->device, "PATH=") || starts_with(entity->device, "UUID=") || starts_with(entity->device, "DEV="))) {
      print_error(_("Device must start with 'PATH=', 'UUID=', or 'DEV=' for line %i\n"), lineno);
   }

   // Validate key
   if (!(strcmp(entity->key, "ASK") == 0 || starts_with(entity->key, "CLEVIS=") || starts_with(entity->key, "KEYFILE="))) {
      print_error(_("Key must start with 'CLEVIS=', 'KEYFILE=' or 'ASK' for line %i\n"), lineno);
   }

   // Parse options
   entity->option_flags = 0;
   token = strtok(option_str, ",");
   char       *end;
   const char *error_msg = _("cannot parse option line %i, reasion: \n\t%s");
   while (token) {
      if (strcmp(token, "none") == 0) {
         break;
      } else if (strcmp(token, "readonly") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_ro;
      } else if (strcmp(token, "no-read-workqueue") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_no_read_wq;
      } else if (strcmp(token, "no-write-workqueue") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_no_write_wq;
      } else if (strcmp(token, "allow-discards") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_target_allow_discards;
      } else if (strcmp(token, "nofail") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_nofail;
      } else if (strcmp(token, "systemd") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_systemd;
      } else if (strcmp(token, "no-map-partition") == 0) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_is_no_map_partition;
      } else if (starts_with(token, "max-unlock-memory=")) {
         entity->option_flags |= 1 << NMOBJ_windhamtab_max_unlock_mem;
         entity->max_unlock_mem = strtoull(token + strlen("max-unlock-memory="), &end, 10);
         if (*end != '\0') {
            print_error(error_msg, lineno, _("bad input for argument \"max-unlock-memory\" -- not a positive integer"));
         }
      } else if (starts_with(token, "max-unlock-time=")) {
         // windhamtab does not support "-" for infinity unlock time
         entity->option_flags |= 1 << NMOBJ_windhamtab_max_unlock_time;
         if (strcmp(token + strlen("max-unlock-time="), "-") == 0) {
            print_error(_("windhamtab file does not support \"-\" for infinity unlock time."));
         }
         entity->max_unlock_time = strtod(token + strlen("max-unlock-time="), &end);
         if (*end != '\0' || entity->max_unlock_time < 0) {
            print_error(error_msg, lineno, _("bad input for argument \"max-unlock-time\" -- not a positive value"));
         }

      } else {
         print_error(_("Unknown option \"%s\" at line %i"), token, 0);
      }

      token = strtok(NULL, ",");
   }
   free(option_str);
   return return_;
}

int open_windhamtab(const char *windhamtab_file) {
   int fd = open(windhamtab_file, O_RDONLY);
   if (fd != -1) {
      return fd;
   }
   if (errno == ENOENT) {
      print_warning(_("Windhamtab file %s does not exist. Creating..."), windhamtab_file);
      fd = open(windhamtab_file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
      if (fd == -1) {
         print_error(_("Cannot create windhantab file."));
      }
      if (write(fd, WINDHAMTABMSG, strlen(WINDHAMTABMSG)) == -1) {
         print_error(_("Cannot write windhantab file."));
      }
      return -1;
   }
   print_error(_("Cannot open windhamtab file: %s"), strerror(errno));
}

WindhamtabEntity *parse_file(const char *filename, int *entity_count, bool is_pass, int pass) {
   int fd = open_windhamtab(filename);
   if (fd == -1) {
      *entity_count = 0;
      return NULL;
   }

   struct stat sb;
   if (fstat(fd, &sb) == -1) {
      perror("Error getting file size");
      close(fd);
      exit(EXIT_FAILURE);
   }

   char *file_content = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
   if (file_content == MAP_FAILED) {
      perror("Error mapping file");
      close(fd);
      exit(EXIT_FAILURE);
   }

   close(fd);

   WindhamtabEntity *entities = NULL;
   *entity_count              = 0;
   char *file                 = file_content;
   bool  is_content;
   int   lineno = 1;
     while (1) {
       entities = realloc(entities, (*entity_count + 1) * sizeof(WindhamtabEntity));
       file     = parse_line(file, &entities[*entity_count], &is_content, lineno);
       if (file == NULL) {
         break;
       }
       if (is_content) {
         if (!is_pass || pass == entities[*entity_count].pass) {
	   (*entity_count)++;
	 }
       }
       lineno++;
     }
     if (!is_content) {
       qsort(entities, *entity_count, sizeof(WindhamtabEntity), (int (*)(const void *, const void *)) entiry_comp);
     }
   if (munmap(file_content, sb.st_size) == -1) {
      perror("Error unmapping file");
   }

   return entities;
}

void free_entities(WindhamtabEntity *entities, int entity_count) {
   for (int i = 0; i < entity_count; i++) {
      free(entities[i].device);
      free(entities[i].key);
   }
   free(entities);
}

void append_entity(const char *windhamtab_location, const char *device, const char *clevis_path, char *options, unsigned short pass) {
   char *device_cpy;

   if (starts_with(device, "/dev/disk/by-partuuid/")) {
      device_cpy = alloca(strlen(device) + 1);
      memcpy(device_cpy, "UUID=", strlen("UUID="));
      strcpy(device_cpy + strlen("UUID="), device + strlen("/dev/disk/by-partuuid/"));
   } else if (starts_with(device, "/dev/disk/by-path/")) {
      device_cpy = alloca(strlen(device) + 1);
      memcpy(device_cpy, "PATH=", strlen("PATH="));
      strcpy(device_cpy + strlen("PATH="), device + strlen("/dev/disk/by-path/"));
   } else {
      device_cpy = alloca(strlen(device) + strlen("DEV=") + 1);
      memcpy(device_cpy, "DEV=", strlen("DEV="));
      strcpy(device_cpy + strlen("DEV="), device);
   }

   char *clevis_path_cpy;
   if (clevis_path == NULL) {
      clevis_path_cpy = "ASK";
   } else {
      clevis_path_cpy = alloca(strlen(clevis_path) + strlen("CLEVIS=") + 1);
      memcpy(clevis_path_cpy, "CLEVIS=", strlen("CLEVIS="));
      strcpy(clevis_path_cpy + strlen("CLEVIS="), clevis_path);
   }

   char buf[snprintf(NULL, 0, "\n%s %s %s %hu\n", device_cpy, clevis_path_cpy, options, pass) + 1];
   sprintf(buf, "\n%s %s %s %hu\n", device_cpy, clevis_path_cpy, options, pass);

   int fd = open_windhamtab(windhamtab_location);
   lseek(fd, 0, SEEK_END);
   if (write(fd, buf, sizeof(buf) - 1) != (ssize_t) sizeof(buf) - 1) {
      print_error(_("Cannot open windhamtab file."));
   }
   close(fd);
}


/* int main(int argc, char *argv[]) { */
/*   if (argc < 2) { */
/*     fprintf(stderr, "Usage: %s <filename>\n", argv[0]); */
/*     return EXIT_FAILURE; */
/*   } */

/*   FILENAME = argv[1]; */

/*   append_entity("/dev/tmpf", NULL, "none", 4); */

/*   int entity_count; */
/*   WindhamtabEntity *entities = parse_file(argv[1], &entity_count); */
/*   if (!entities) { */
/*     return EXIT_FAILURE; */
/*   } */

/*   // Output parsed entities for demonstration purposes */
/*   for (int i = 0; i < entity_count; i++) { */
/*     printf("Entity %d:\n", i + 1); */
/*     printf("  Device: %s\n", entities[i].device); */
/*     printf("  Key: %s\n", entities[i].key); */
/*     printf("  Options: "); */
/*     for (int j = 0; j < MAX_OPTIONS && entities[i].options[j]; j++) { */
/*       printf("%s ", entities[i].options[j]); */
/*     } */
/*     printf("\n  Pass: %hu\n", entities[i].pass); */
/*   } */

/*   free_entities(entities, entity_count); */
/*   return EXIT_SUCCESS; */
/* } */
