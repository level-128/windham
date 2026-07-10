#ifndef INCL_INIT
#define INCL_INIT

#include "../include/windham_const.h"

void frontend_init(int argc, char *argv[]);


#ifndef WINDHAM_ISOC
#include "GNU_Linux/init.c"
#else
#include "ISOC/init.c"
#endif

#endif