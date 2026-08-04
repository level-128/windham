#include <stdbool.h>
#include <stdio.h>
#include "../../include/windham_const.h"
#include "../../library/include_all_libs.c"


// Emscripten has no portable way to query system memory. Report UINTPTR_MAX
// (unknown / unlimited) so key derivation always assumes enough memory.
void get_system_info() {
   sys_info.free_ram  = UINTPTR_MAX;
   sys_info.free_swap = UINTPTR_MAX;
   sys_info.total_ram = UINTPTR_MAX;
}


void frontend_init(int argc, char *argv[]){

    setvbuf(stdout, NULL, _IONBF, 0);
    init_val->is_secure_env = false;
    init_val->is_shebang = false;
    init_val->is_color_print = false;
    init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_SYSTEM;
}
