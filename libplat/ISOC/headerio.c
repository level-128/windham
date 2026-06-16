//
// Created by level on 25-5-20.
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../libsrc/srclib.c"


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

   const int seek_origin = (offset < 0) ? SEEK_END : SEEK_SET;

   if (fseek(fp, offset, seek_origin) != 0) {
      print_error(_("Failed to seek in %s: %s"), device, strerror(errno));
      fclose(fp);
      return;
   }

   size_t elements_processed;
   if (is_read) {
      elements_processed = fread(data, sizeof(Data), 1, fp);
      if (elements_processed != 1) {
         if (ferror(fp)) {
            print_error(_("Failed to read %s: %s"), device, strerror(errno));
         } else {
            print_error(_("Failed to read %s: unexpected EOF"), device);
         }
      }
   } else {
      elements_processed = fwrite(data, sizeof(Data), 1, fp);
      if (elements_processed != 1) {
         print_error(_("Failed to write %s: %s"), device, strerror(errno));
      }
      fflush(fp);
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

   if (fseek(fp, offset, SEEK_SET) != 0) {
      print_error(_("Failed to seek aux zone on %s: %s"), device, strerror(errno));
      fclose(fp);
      return;
   }

   size_t elements_processed;
   if (is_read) {
      elements_processed = fread(aux_zone, aux_zone_size, 1, fp);
   } else {
      elements_processed = fwrite(aux_zone, aux_zone_size, 1, fp);
      fflush(fp);
   }
   if (elements_processed != 1) {
      print_error(_("Failed to %s aux zone on %s: %s"),
                  is_read ? "read" : "write", device, strerror(errno));
   }
   fclose(fp);
}