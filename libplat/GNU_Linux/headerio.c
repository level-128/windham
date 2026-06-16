#include <stdint.h>
#include <fcntl.h>

#include "../../libsrc/srclib.c"



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

void operate_aux_zone_on_device(uint8_t *aux_zone, size_t aux_zone_size, const char *device, int64_t offset, bool is_read) {
   const int fp = open(
      device,
      is_read ? O_RDONLY : O_WRONLY);
   if (fp < 0) {
      print_error(_("Failed to open %s for aux zone: %s"), device, strerror(errno));
   }

   if (lseek(fp, offset, SEEK_SET) < 0) {
      print_error(_("Failed to seek aux zone on %s: %s"), device, strerror(errno));
   }

   ssize_t result;
   if (is_read) {
      result = read(fp, aux_zone, aux_zone_size);
   } else {
      result = write(fp, aux_zone, aux_zone_size);
   }
   if (result != (ssize_t)aux_zone_size) {
      print_error(_("Failed to %s aux zone on %s: %s"),
                  is_read ? "read" : "write", device, strerror(errno));
   }
   close(fp);
}