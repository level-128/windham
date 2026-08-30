#ifndef INCL_HEADERIO
#define INCL_HEADERIO

#include <stdint.h>
#include "../include/windham_const.h"


void operate_header_on_device(Data *data, const char *device, int64_t offset, bool is_read);

void operate_aux_zone_on_device(uint8_t *aux_zone, size_t aux_zone_size, const char *device, int64_t offset, bool is_read);

/* Platform-abstracted device I/O -- handle is opaque (int fd / FILE *).
   Returns bytes transferred on success, -1 on error.                     */
void   *device_open(const char *path, bool writable);
void    device_close(void *handle);
int     device_seek(void *handle, int64_t offset);
int64_t device_read(void *handle, void *buf, size_t count);
int64_t device_write(void *handle, const void *buf, size_t count);

/* Probe for the existence of a file/device without opening it for I/O. */
bool device_is_exist(const char *path);

/* Create a new file and return a writable handle for it.
   Fails if the file already exists.                                     */
void *device_create(const char *path);

#ifdef WINDHAM_PLAT_GNU_LINUX
#include "GNU_Linux/headerio.c"
#else
#include "ISOC/headerio.c"
#endif

#endif