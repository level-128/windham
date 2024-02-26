//
// Created by level-128 on 1/19/24.
//

#include <windham_const.h>

#include "bklibact.c"
#include "bklibcreat.c"
#include "bklibhelp.c"
#include "bklibkey.c"
#include "bklibopen.c"
#include "../library_intrnlsrc/libloop.c"
#include "../library_intrnlsrc/libexit.c"


void is_running_as_root() {
	if (getuid() != 0) {
		print_error(_("The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible without root permission")) {}
	}
}

void init_enclib(char * generator_addr) {
	FLAG_clear_internal_memory = 0;
	random_fd = fopen(generator_addr, "r");
	if (random_fd == NULL) {
		print_error(_("Failed to initialize random generator."));
	}
}

void init() {
	environ = malloc(sizeof(char *));
	*environ = NULL;
	exit_init();
	init_enclib("/dev/urandom");
	get_system_info();
	mapper_init();
	init_libloop();
}
