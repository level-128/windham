#include <stdbool.h>
#include <stdio.h>
#include "../../include/windham_const.h"
#include "../../library/include_all_libs.c"


void frontend_init(int argc, char *argv[]){

    setvbuf(stdout, NULL, _IONBF, 0);
    init_val->is_secure_env = false;
    init_val->is_shebang = false;
    init_val->is_color_print = false;
    init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_SYSTEM;
}
