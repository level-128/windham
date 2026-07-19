/*
 * ISOC / WASI terminal primitives — canonical line-buffered input.
 *
 * Defines:
 *   terminal_disable_echo()   — no-op (echo is terminal-controlled)
 *   terminal_restore_echo()   — no-op
 *   terminal_read_char()      — read one byte from stdin (unbuffered)
 *   WINDHAM_TERM_RAW          — 0 (canonical terminal)
 *   get_key_input_from_the_console_systemd() — error stub
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define WINDHAM_TERM_RAW 0

#ifndef WINDHAM_UTF_32
static bool stdin_is_unbuffered = false;
#endif

static void terminal_disable_echo(void) {
}

static void terminal_restore_echo(void) {
}

static int terminal_read_char(void) {
#ifndef WINDHAM_UTF_32
	if (!stdin_is_unbuffered) {
		setvbuf(stdin, NULL, _IONBF, 0);
		stdin_is_unbuffered = true;
	}
#endif
	return getchar();
}

unsigned get_key_input_from_the_console_systemd(const char *WINDHAM_ATTRIBUTE(maybe_unused) device,
                                                 char32_t password[MAX_PASSWORD_INPUT_LEN]) {
	(void)password;
	print_error(_("\"--systemd-dialog\" is not available under ISO C. Use --key, --key-file, or interactive input instead."));
	return 0;
}
