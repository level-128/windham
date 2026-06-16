#ifndef INCL_HEADERIO
#define INCL_HEADERIO

#include <stdint.h>
#include "../include/windham_const.h"


void operate_header_on_device(Data *data, const char *device, int64_t offset, bool is_read);

void operate_aux_zone_on_device(uint8_t *aux_zone, size_t aux_zone_size, const char *device, int64_t offset, bool is_read);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/headerio.c"
#else
#include "ISOC/headerio.c"
#endif

#endif