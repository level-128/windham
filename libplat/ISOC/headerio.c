//
// Created by level on 25-5-20.
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../libsrc/srclib.c"


/* ── Platform device I/O (stdio FILE *) ────────────────────── */

int device_seek(void *handle, int64_t offset) {
	return fseek((FILE *)handle, (long)offset, SEEK_SET);
}

int64_t device_read(void *handle, void *buf, size_t count) {
	return (int64_t)fread(buf, 1, count, (FILE *)handle);
}

int64_t device_write(void *handle, const void *buf, size_t count) {
	return (int64_t)fwrite(buf, 1, count, (FILE *)handle);
}


void operate_header_on_device(Data *data, const char *device, int64_t offset, bool is_read) {
   assert(offset % 4 == 0);
   const char *mode = is_read ? "rb" : "r+b";
   FILE *fp = fopen(device, mode);
   if (fp == NULL) {
      print_error(_("Failed to open %s: %s"), device, strerror(errno));
      return;
   }

   if (setvbuf(fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s: %s"), device, strerror(errno));
      fclose(fp);
      return;
   }

   void *handle = (void *)fp;
   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek in %s: %s"), device, strerror(errno));
      fclose(fp);
      return;
   }

   int64_t result;
   if (is_read) {
      result = device_read(handle, data, sizeof(Data));
   } else {
      result = device_write(handle, data, sizeof(Data));
   }
   if (result != (int64_t)sizeof(Data)) {
      if (is_read)
         print_error(_("Failed to read %s: %s"), device, strerror(errno));
      else
         print_error(_("Failed to write %s: %s"), device, strerror(errno));
   }

   fclose(fp);
}

void operate_aux_zone_on_device(uint8_t *aux_zone, size_t aux_zone_size, const char *device, int64_t offset, bool is_read) {
   const char *mode = is_read ? "rb" : "r+b";
   FILE *fp = fopen(device, mode);
   if (fp == NULL) {
      print_error(_("Failed to open %s for aux zone: %s"), device, strerror(errno));
      return;
   }

   if (setvbuf(fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s: %s"), device, strerror(errno));
      fclose(fp);
      return;
   }

   void *handle = (void *)fp;
   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek aux zone on %s: %s"), device, strerror(errno));
      fclose(fp);
      return;
   }

   int64_t result;
   if (is_read) {
      result = device_read(handle, aux_zone, aux_zone_size);
   } else {
      result = device_write(handle, aux_zone, aux_zone_size);
   }
   if (result != (int64_t)aux_zone_size) {
      print_error(_("Failed to %s aux zone on %s: %s"),
                  is_read ? "read" : "write", device, strerror(errno));
   }
   fclose(fp);
}