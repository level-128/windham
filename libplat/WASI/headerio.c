//
// Emscripten platform device I/O — virtual FS (stdio FILE *)
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "../../libsrc/srclib.c"


struct device_handle {
	FILE    *fp;
	uint64_t offset;
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

int device_seek(void *handle, int64_t offset) {
	struct device_handle *h = handle;
	int64_t delta = offset - (int64_t)h->offset;
	if (delta == 0) return 0;
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
   void *handle = device_open(device, is_read ? false : true);
   if (!handle) { print_error(_("Failed to open %s: %s"), device, strerror(errno)); return; }
   struct device_handle *h = handle;
   if (setvbuf(h->fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s"), device); device_close(handle); return;
   }
   device_seek(handle, offset);
   int64_t result = is_read ? device_read(handle, data, sizeof(Data))
                            : device_write(handle, data, sizeof(Data));
   if (result != (int64_t)sizeof(Data))
      print_error(_("Failed to %s data on %s"), is_read ? "read" : "write", device);
   device_close(handle);
}

void operate_aux_zone_on_device(uint8_t *aux, size_t size, const char *device, int64_t offset, bool is_read) {
   void *handle = device_open(device, is_read ? false : true);
   if (!handle) { print_error(_("Failed to open %s for aux zone"), device); return; }
   struct device_handle *h = handle;
   if (setvbuf(h->fp, NULL, _IONBF, 0) != 0) {
      print_error(_("Failed to set buffer mode for %s"), device); device_close(handle); return;
   }
   device_seek(handle, offset);
   int64_t result = is_read ? device_read(handle, aux, size)
                            : device_write(handle, aux, size);
   if (result != (int64_t)size)
      print_error(_("Failed to %s aux zone on %s"), is_read ? "read" : "write", device);
   device_close(handle);
}
