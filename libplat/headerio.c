#ifndef INCL_HEADERIO
#define INCL_HEADERIO

#include <stdio.h>

void action_new_check_crypt_support_status(const char *);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/headerio.c"
#else
#include "ISOC/headerio.c"
#endif

#endif