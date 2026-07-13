//
// Created by level on 25-5-20.
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "../../libsrc/srclib.c"


/* ── Platform device I/O (stdio FILE *) ────────────────────── */
/* On 32-bit platforms long is only 32-bit, so fseek(long, SEEK_SET)
   cannot represent offsets beyond 2 GiB.  We wrap the FILE * in a
   small struct that tracks the absolute byte offset and uses
   fseek(SEEK_CUR) in multiple steps when the delta exceeds LONG_MAX.*/

struct device_handle {
	FILE    *fp;
	uint64_t offset;   /* current absolute byte position */
};

void *device_open(const char *path, bool writable) {
	struct device_handle *h = malloc(sizeof(*h));
	if (!h) return NULL;
	h->fp = fopen(path, writable ? "r+b" : "rb");
	if (!h->fp) { free(h); return NULL; }
	h->offset = 0;
	return h;
}

void device_close(void *handle) {
	struct device_handle *h = handle;
	if (h) { fclose(h->fp); free(h); }
}

int device_get_fd(void *handle) {
	(void)handle;
	return -1;  /* no fd under stdio */
}

int device_seek(void *handle, int64_t offset) {
	struct device_handle *h = handle;
	int64_t delta = offset - (int64_t)h->offset;
	if (delta == 0) return 0;

	/* Step in LONG_MAX chunks via SEEK_CUR so the cast to long
	   never overflows, even on 32-bit platforms.               */
	while (delta > 0) {
		long step = delta > LONG_MAX ? LONG_MAX : (long)delta;
		if (fseek(h->fp, step, SEEK_CUR) != 0) return -1;
		delta -= step;
	}
	while (delta < 0) {
		long step = delta < LONG_MIN ? LONG_MIN : (long)delta;
		if (fseek(h->fp, step, SEEK_CUR) != 0) return -1;
		delta -= step;
	}
	h->offset = (uint64_t)offset;
	return 0;
}

int64_t device_read(void *handle, void *buf, size_t count) {
	struct device_handle *h = handle;
	int64_t n = (int64_t)fread(buf, 1, count, h->fp);
	h->offset += (uint64_t)n;
	return n;
}

int64_t device_write(void *handle, const void *buf, size_t count) {
	struct device_handle *h = handle;
	int64_t n = (int64_t)fwrite(buf, 1, count, h->fp);
	h->offset += (uint64_t)n;
	return n;
}


void operate_header_on_device(Data *data, const char *device, int64_t offset, bool is_read) {
   assert(offset % 4 == 0);
   void *handle = device_open(device, is_read ? false : true);
   if (!handle) {
      print_error(_("Failed to open %s: %s"), device, strerror(errno));
      return;
   }

   struct device_handle *h = handle;
   if (setvbuf(h->fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s: %s"), device, strerror(errno));
      device_close(handle);
      return;
   }

   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek in %s: %s"), device, strerror(errno));
      device_close(handle);
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

   device_close(handle);
}

void operate_aux_zone_on_device(uint8_t *aux_zone, size_t aux_zone_size, const char *device, int64_t offset, bool is_read) {
   void *handle = device_open(device, is_read ? false : true);
   if (!handle) {
      print_error(_("Failed to open %s for aux zone: %s"), device, strerror(errno));
      return;
   }

   struct device_handle *h = handle;
   if (setvbuf(h->fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s: %s"), device, strerror(errno));
      device_close(handle);
      return;
   }

   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek aux zone on %s: %s"), device, strerror(errno));
      device_close(handle);
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
   device_close(handle);
}