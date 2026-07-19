/*
 * GNU/Linux terminal primitives — raw mode, per-keystroke input.
 *
 * Defines:
 *   terminal_disable_echo()   — switch to raw non-canonical no-echo mode
 *   terminal_restore_echo()   — restore original termios settings
 *   terminal_read_char()      — read one byte from stdin
 *   WINDHAM_TERM_RAW          — 1 (raw terminal, ANSI escapes available)
 *   get_key_input_from_the_console_systemd()
 */

#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <wchar.h>

#define WINDHAM_TERM_RAW 1

static void terminal_disable_echo(void) {
	struct termios raw = oldt;
	raw.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &raw);
}

static void terminal_restore_echo(void) {
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

static int terminal_read_char(void) {
	return getchar();
}

unsigned get_key_input_from_the_console_systemd(const char *device, char32_t password[MAX_PASSWORD_INPUT_LEN]) {
	int exec_ret_val;
	char *dup_stdout = NULL;
	char *exec_dir[] = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL};
	size_t dup_stdout_len;
	char password_prompt[strlen("password for ") + strlen(device) + strlen(":") + 1];
	sprintf(password_prompt, "password for %s:", device);

	if (exec_name(
			"systemd-ask-password",
			exec_dir,
			-1,
			&dup_stdout,
			&dup_stdout_len,
			&exec_ret_val,
			NMOBJ_exec_name_wait_child,
			password_prompt,
			NULL) == false) {
		if (errno == ENOENT) {
			print_error(
				_("\"systemd-ask-password\" is not available. Param \"--systemd-dialog\" only supports system with systemd as init."));
		} else {
			print_error(_("failed to call \"systemd-ask-password\"."));
		}
	} else if (exec_ret_val != 0) {
		print_error(_("Cannot get password from systemd service"));
	}

	dup_stdout[dup_stdout_len - 1] = '\x00';

	const char *p = dup_stdout;
	unsigned index = 0;
	mbstate_t mbs = {0};

	while (*p && index + 1 < MAX_PASSWORD_INPUT_LEN) {
		char32_t wc = 0;
		size_t rc = mbrtoc32(&wc, p, MB_CUR_MAX, &mbs);

		if (rc == 0) break;
		if (rc == (size_t)-1 || rc == (size_t)-2) {
			print_error(_("Invalid multibyte sequence in systemd password output"));
		}
		password[index++] = wc;
		p += rc;
	}
	password[index] = 0;
	free(dup_stdout);
	return index;
}
