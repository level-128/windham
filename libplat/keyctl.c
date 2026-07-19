#ifndef INCL_KERKEY
#define INCL_KERKEY

#include <stdbool.h>

bool is_kernel_keyring_exist;


#if defined(WINDHAM_PLAT_WASI)
#include "WASI/keyctl.c"
#elif defined(WINDHAM_PLAT_GNU_LINUX) && !defined(CFG_NO_MODULE_KEYRING)
#include "GNU_Linux/keyctl.c"
#else
#include "ISOC/keyctl.c"
#endif



#endif