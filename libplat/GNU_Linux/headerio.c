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