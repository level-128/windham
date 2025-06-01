#ifndef INCL_KERKEY
#define INCL_KERKEY

#include <stdbool.h>

bool is_kernel_keyring_exist;


#if !defined(WINDHAM_ISOC) && !defined(NO_KEYCTL)
#include "GNU_Linux/keyctl.c"
#else
#include "ISOC/keyctl.c"
#endif



#endif