/*
 * WASI / Emscripten platform init.
 *
 * WASI (wasi-sdk):  no /dev, no locale, CSPRNG via __wasi_random_get
 * Emscripten:       same baseline; Emscripten provides system()
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../library/include_all_libs.c"


#ifndef __EMSCRIPTEN__
/* WASI has no process spawning — stub out system().
   Emscripten provides its own system() via the runtime. */
int system(const char *command) {
    (void)command;
    return -1;
}
#endif


void frontend_init(int argc, char *argv[]){

    setvbuf(stdin, NULL, _IONBF, 0);

    init_val->is_secure_env = false;
    init_val->is_shebang = false;
    init_val->is_color_print = false;

    init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_SYSTEM;

    if (timespec_get(
        &init_val->initial_internal_entropy_source.time,
        TIME_UTC) != TIME_UTC){
            init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_WEAK;
    }
}
