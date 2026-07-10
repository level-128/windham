// driver_shell.c — shell/system() driver (was ISOC/mapper.c)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../include/windham_const.h"
#include "../libsrc/srclib.c"

#define MAPPER_BACKEND_OPEN_STRING  "MAPPER_BACKEND_OPEN:\xff"
volatile const char mapper_backend_open_cmd[256] = MAPPER_BACKEND_OPEN_STRING;

static char* format_string(const char* fmt, const char* arr[8]) {
   size_t total_len = 0;
   const char* p = fmt;
   while (*p) {
      if (*p == '\xff') { const char c = *(p + 1); int idx = 0;
         switch (c) { case 'a':idx=0;break;case 's':idx=1;break;case 'd':idx=2;break;
                      case 'f':idx=3;break;case 'g':idx=4;break;case 'h':idx=5;break;
                      case 'j':idx=6;break;case 'k':idx=7;break;
                      default: return NULL; }
         total_len += strlen(arr[idx]); p += 2;
      } else { total_len++; p++; }
   }
   char* buf = malloc(total_len + 1); if (!buf) return NULL;
   char* dest = buf; p = fmt;
   while (*p) {
      if (*p == '\xff') { const char c = *(p + 1); int idx = 0;
         switch (c) { case 'a':idx=0;break;case 's':idx=1;break;case 'd':idx=2;break;
                      case 'f':idx=3;break;case 'g':idx=4;break;case 'h':idx=5;break;
                      case 'j':idx=6;break;case 'k':idx=7;break; default: break; }
         const char* sub = arr[idx]; size_t l = strlen(sub);
         memcpy(dest, sub, l); dest += l; p += 2;
      } else { *dest++ = *p++; }
   }
   *dest = '\0'; return buf;
}

static char * parse_cmd(const char *device, const char *name, const char *enc_type,
                        const char *password, char uuid_str[37],
                        size_t start_sector, size_t end_sector, size_t block_size) {
   char * cmdend = strstr((const char *)mapper_backend_open_cmd, "\x03");
   if (!cmdend) return NULL;
   char * cmdstart = strstr((const char *)mapper_backend_open_cmd, MAPPER_BACKEND_OPEN_STRING);
   if (!cmdstart || cmdstart >= cmdend) return NULL;
   cmdstart += strlen(MAPPER_BACKEND_OPEN_STRING);
   size_t cmdlen = (size_t)(cmdend - cmdstart);
   char * fmt = malloc(cmdlen + 1);
   memcpy(fmt, cmdstart, cmdlen); fmt[cmdlen] = 0;
   char ss[32], es[32], bs[32];
   sprintf(ss, "%zu", start_sector); sprintf(es, "%zu", end_sector); sprintf(bs, "%zu", block_size);
   const char * arr[] = {device, name, enc_type, password, uuid_str, ss, es, bs};
   char * ret = format_string(fmt, arr);
   free(fmt); return ret;
}

// ── Driver interface ───────────────────────────────

static void shell_init(const char *driver_name) {
   (void)driver_name;
   is_device_mapper_available = (system(NULL) != 0);
}

static int shell_try_create(const char *file, const char *enc, const char *tmp) {
   (void)file; (void)enc; (void)tmp;
   if (!is_device_mapper_available) return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
   return EMOBJ_try_create_crypt_mapping_OK;
}

static int shell_create(const char *device, const char *name, const char *enc_type,
                        const char *password, char uuid_str[37],
                        size_t start_sector, size_t end_sector, size_t block_size,
                        bool ro, bool ad, bool nrwq, bool nwwq) {
   (void)ro; (void)ad; (void)nrwq; (void)nwwq;
   if (!is_device_mapper_available) {
      printf("no command processor available.\n");
      return -1;
   }
   char *cmd = parse_cmd(device, name, enc_type, password, uuid_str, start_sector, end_sector, block_size);
   if (!cmd) {
      printf("Cannot map device %s to %s (no command string).\n", device, name);
      return -1;
   }
   int ret = system(cmd);
   free(cmd);
   printf("mapper cmd returned %i\n", ret);
   return ret;
}

static bool shell_linear_map(const char *d, const char *n, uint64_t s, uint64_t sz, const char *u) {
   (void)d; (void)n; (void)s; (void)sz; (void)u;
   return false;
}

static void shell_map_partitions(const char *n, bool b) { (void)n; (void)b; }

Driver driver_shell = {
   .name = "shell", .init = shell_init, .try_create = shell_try_create,
   .create = shell_create, .remove = NULL,
   .remove_by_uuid = NULL, .linear_map = shell_linear_map,
   .map_partition_table = shell_map_partitions,
};
