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

#ifndef WINDHAM_ISOC
#include "GNU_Linux/headerio.c"
#else
#include "ISOC/headerio.c"
#endif

#endif