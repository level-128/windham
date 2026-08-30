#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "../../libsrc/srclib.c"


/* ── Platform device I/O (POSIX fd) ────────────────────────── */

void *device_open(const char *path, bool writable) {
	int fd = open(path, writable ? O_RDWR : O_RDONLY);
	if (fd < 0) return NULL;
	return (void *)(intptr_t)fd;
}

void device_close(void *handle) {
	if (handle) close((int)(intptr_t)handle);
}

int device_seek(void *handle, int64_t offset) {
	return lseek((int)(intptr_t)handle, offset, SEEK_SET) == (off_t)-1 ? -1 : 0;
}

int64_t device_read(void *handle, void *buf, size_t count) {
	return (int64_t)read((int)(intptr_t)handle, buf, count);
}

int64_t device_write(void *handle, const void *buf, size_t count) {
	return (int64_t)write((int)(intptr_t)handle, buf, count);
}

bool device_is_exist(const char *path) {
	return access(path, F_OK) == 0;
}

void *device_create(const char *path) {
	int fd = open(path, O_RDWR | O_CREAT | O_EXCL, S_IRUSR);
	if (fd < 0) return NULL;
	return (void *)(intptr_t)fd;
}


void operate_header_on_device(Data * data, const char * device, int64_t offset, bool is_read) {
   ssize_t result;
   assert(offset % 4 == 0);
   const int fp = open(
      device,
      O_DSYNC | (is_read
                    ? O_RDONLY
                    : O_WRONLY));
   if (fp < 0) {
      print_error(_("Failed to open %s: %s"), device, strerror(errno));
   }

   void *handle = (void *)(intptr_t)fp;
   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek %s: %s"), device, strerror(errno));
   }
   if (is_read) {
      result = device_read(handle, data, sizeof(Data));
   } else {
      result = device_write(handle, data, sizeof(Data));
   }
   if (result != sizeof(Data)) {
      print_error(_("Failed to %s %s: %s\""), is_read ? "read" : "write", device, strerror(errno));
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

   void *handle = (void *)(intptr_t)fp;
   if (device_seek(handle, offset) != 0) {
      print_error(_("Failed to seek aux zone on %s: %s"), device, strerror(errno));
   }
   ssize_t result;
   if (is_read) {
      result = device_read(handle, aux_zone, aux_zone_size);
   } else {
      result = device_write(handle, aux_zone, aux_zone_size);
   }
   if (result != (ssize_t)aux_zone_size) {
      print_error(_("Failed to %s aux zone on %s: %s (offset=%lld)"),
                  is_read ? "read" : "write", device, strerror(errno), (long long)offset);
   }
   close(fp);
}