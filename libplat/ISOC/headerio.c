//
// Created by level on 25-5-20.
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../libsrc/srclib.c"

uintmax_t isoc_get_file_size(FILE *stream){
   fpos_t stored_pos;
   if (fgetpos(stream, &stored_pos)){
      perror("fgetpos");
      exit(1);
   }
   if (fseek(stream, 0, SEEK_END)){
      perror("cannot SEEK_END, is device pipe?");
      exit(1);
   }

   uintmax_t sum_res = 0;
   if (sizeof(uintmax_t) != sizeof(long)){
      while (fseek(stream, LONG_MIN, SEEK_CUR) == 0){
         sum_res -= LONG_MIN;
      }
   }

   long int res = ftell(stream);
   if (res == -1L){
      perror("cannot get file size");
      exit(1);
   }
   sum_res += res;
   if (fsetpos(stream, &stored_pos)){
      perror("fsetpos");
      exit(1);
   }
   return sum_res;
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