#ifndef INCL_HEADERIO
#define INCL_HEADERIO

#include <stdint.h>
#include "../include/windham_const.h"


void operate_header_on_device(Data *data, const char *device, int64_t offset, bool is_read);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/headerio.c"
#else
#include "ISOC/headerio.c"
#endif

#endif