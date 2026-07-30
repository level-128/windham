// CLI frontend for Windham.

#define IS_FRONTEND_ENTRY

#include "isoc_config_c.h"

#include "libplat/init.c"
#include "include/windham_const.h"
#include "main.c"


// -- main --------------------------------------------

int main(int argc, char *argv[]) {
    init_val = malloc(sizeof(PlatInitVal));
    if (!init_val) { perror("malloc"); exit(1); }
    frontend_init(argc, argv);
    windham_main(argc, argv);
    return 0;
}
