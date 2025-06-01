#ifndef INCL_HEADERIO
#define INCL_HEADERIO

#include <stdio.h>

void action_new_check_crypt_support_status(const char *);

uintmax_t isoc_get_file_size(FILE *stream);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/headerio.c"
#else
#include "ISOC/headerio.c"
#endif

#endif