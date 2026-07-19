#ifndef INCL_INIT
#define INCL_INIT

#include <stdlib.h>
#include "../include/windham_const.h"

void frontend_init(int argc, char *argv[]);

void fin_device(void);

void windham_exit(int exitno) {
   fin_device();
#if !defined(IS_FRONTEND_ENTRY) && defined(WINDHAM_PLAT_GNU_LINUX)
   if (exitno != EXIT_SUCCESS) longjmp(exit_jmp, 1);
#else
   exit(exitno);
#endif
}

#ifdef WINDHAM_PLAT_GNU_LINUX
#include "GNU_Linux/init.c"
#else
#include "ISOC/init.c"
#endif

#endif