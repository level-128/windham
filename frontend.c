// CLI frontend for Windham.

#define IS_FRONTEND_ENTRY

#include "libplat/init.c"
#include "include/windham_const.h"
#include "main.c"


// -- main --------------------------------------------

int main(int argc, char *argv[]) {
    init_val = malloc(sizeof(PlatInitVal));
    if (!init_val) { perror("malloc"); exit(1); }
    frontend_init(argc, argv);
    main_(argc, argv);
    return 0;
}
