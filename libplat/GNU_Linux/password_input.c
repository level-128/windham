#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <wchar.h>

#define MIN_KEY_CHAR 7

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

static int bklibkey_check_hex(int ch) {
	if (ch >= 'A' && ch <= 'F') {
		return ch - 'A' + 10;
	}
	if (ch >= '0' && ch <= '9') {
		return ch - '0';
	}
	if (ch >= 'a' && ch <= 'f') {
		return ch - 'a' + 10;
	}
	return -1;
}

unsigned get_password_input(char32_t password[MAX_PASSWORD_INPUT_LEN], bool *out_is_unicode) {
	terminal_disable_echo();
	*out_is_unicode = false;

	bool is_echo = false;
	bool is_unicode = false;
	unsigned index = 0;
	uint8_t disp_width[MAX_PASSWORD_INPUT_LEN];
		bool unicode_help_shown = false;

	/* ch needs to be in scope for both unicode and text mode blocks */
	int ch;

	while (index < MAX_PASSWORD_INPUT_LEN - 1) {

		/* ---- UNICODE MODE (before outer read to avoid blocking on getchar) ---- */
		if (is_unicode) {
			if (!unicode_help_shown) {
				unicode_help_shown = true;
				*out_is_unicode = true;
				printf("\n");
				printf(_(
					"Unicode mode: enter a Unicode code point as up to 8 hex digits after each \"U+\" prompt.\n"
					"  Press Enter on an empty line to display all characters (does not exit).\n"
					"  Enter \"0\" (U+0000) to finish without display.\n"
					"  Enter \"_\" to delete the previous character.\n"
					"  Press Backspace on an empty code point to delete the previous character.\n"));
			}

			printf("\nU+");
			fflush(stdout);

			char hex_buf[9] = {0};
			int hex_len = 0;

			while (1) {
				ch = terminal_read_char();

				if (ch == '\n') {
					if (hex_len == 0) {
						/* Empty line: display all characters in-place, then resume */
						printf("\r\033[K");
						if (index > 0) {
							char utf8_out[8]; // MB_CUR_MAX <= 6, + 1 for NUL
							mbstate_t mbs;
							for (unsigned i = 0; i < index; i++) {
								if (i > 0) printf(" ");
								mbs = (mbstate_t){0};
								size_t len = c32rtomb(utf8_out, password[i], &mbs);
								if (len != (size_t)-1) {
									utf8_out[len] = 0;
									printf("%s", utf8_out);
								} else {
									printf("U+%08X", (unsigned)password[i]);
								}
							}
						} else {
							printf("%s", _("(no characters entered)"));
						}
						fflush(stdout);

						/* Wait for Enter to dismiss */
						while (terminal_read_char() != '\n') {}

						/* Replace current line with U+ prompt */
						printf("\r\033[K");
						printf("U+");
						fflush(stdout);
						memset(hex_buf, 0, sizeof(hex_buf));
						hex_len = 0;
						continue;
					}

					/* Underscore: delete previous character */
					if (hex_len == 1 && hex_buf[0] == '_') {
						if (index > 0) {
							index--;
							if (disp_width[index] > 0) {
								for (int k = 0; k < disp_width[index]; k++) {
									printf("\b \b");
								}
								printf("\b \b");
							}
						}
						break; /* exit inner while, outer loop reprints U+ */
					}

					/* Parse hex value */
					hex_buf[hex_len] = 0;
					char *endptr;
					unsigned long val = strtoul(hex_buf, &endptr, 16);
					if (*endptr != 0 || val > 0x10FFFF) {
						putchar(7);
						break; /* invalid: re-prompt */
					}

					if (val == 0) {
						printf("\n");
						goto END;
					}

					password[index] = (char32_t)val;

					/* Display the character as multibyte */
					printf(" ");
					char utf8_out[MB_CUR_MAX + 1];
					mbstate_t mbs = {0};
					size_t len = c32rtomb(utf8_out, (char32_t)val, &mbs);
					if (len != (size_t)-1) {
						utf8_out[len] = 0;
						printf("%s", utf8_out);
						disp_width[index] = (uint8_t)len;
					} else {
						printf("U+%08X", (unsigned)val);
						disp_width[index] = 0;
					}
					putchar(' ');

					index++;
					break; /* exit inner while, outer loop reprints U+ */
				}

				if (ch == '\x7f') { /* backspace */
					if (hex_len > 0) {
						hex_len--;
						printf("\b \b");
						continue;
					}

					/* hex buffer empty: move to previous line and overwrite (GNU/Linux) */
					if (index > 0) {
						index--;
						printf("\033[A\r\033[K");
						printf("U+");
						fflush(stdout);
					} else {
						putchar(7);
					}
					continue;
				}

				if (ch == '_' && hex_len == 0) {
					hex_buf[0] = '_';
					hex_len = 1;
					putchar('_');
					continue;
				}

				int hex_val = bklibkey_check_hex(ch);
				if (hex_val >= 0 && hex_len < 8) {
					hex_buf[hex_len++] = (char)ch;
					putchar(ch);
				} else {
					putchar(7);
				}
			}
			/* inner while exited via break — restart outer loop for next U+ */
			continue;
		}

		/* ---- TEXT MODE ---- */

		int ch = terminal_read_char();

		if (ch == '\n') {
			if (index == 0) {
				print_error(_("Empty input. Password required."));
			}
			password[index] = 0;
			goto END;
		}

		if (ch == '\t') {
			if (is_echo == true) {
				putchar(7);
				continue;
			}
			char *msg;
			if (index == 0) {
				msg = _("press tab to echo; press space for unicode mode");
			} else {
				msg = _("press tab to echo");
			}

			printf("%s", msg);
			fflush(stdout);
			ch = terminal_read_char();

			printf("\r");
			for (unsigned i = 0; i < strlen(msg); i++) {
				printf(" ");
			}
			printf("\r");
			fflush(stdout);

			if (ch == '\t') {
				password[index] = 0;
				for (unsigned i = 0; i < index; i++) {
					putchar((unsigned)password[i]);
				}
				fflush(stdout);
				is_echo = true;
			}
			if (ch == ' ' && index == 0) {
				is_unicode = true;
			}
			continue;
		}

		if (ch == '\x7f') {
			if (index == 0) {
				putchar(7);
				continue;
			}
			index--;
			if (is_echo) {
				for (int k = 0; k < disp_width[index]; k++) {
					printf("\b \b");
				}
			}
			continue;
		}

		/* Decode UTF-8 to char32_t */
		int utf8_len = 1;
		unsigned char lead = (unsigned char)ch;

		if ((lead & 0x80) == 0x00) {
			utf8_len = 1;
		} else if ((lead & 0xE0) == 0xC0) {
			utf8_len = 2;
		} else if ((lead & 0xF0) == 0xE0) {
			utf8_len = 3;
		} else if ((lead & 0xF8) == 0xF0) {
			utf8_len = 4;
		} else {
			putchar(7);
			continue;
		}

		char utf8_buf[5] = {(char)ch, 0, 0, 0, 0};

		for (int j = 1; j < utf8_len; j++) {
			int next = terminal_read_char();
			if (next == '\n') {
				putchar(7);
				if (index == 0 && j == 1 && utf8_len <= 1) {
					goto END_EMPTY;
				}
				continue;
			}
			utf8_buf[j] = (char)next;
		}

		mbstate_t mbs = {0};
		char32_t wc = 0;
		size_t rc = mbrtoc32(&wc, utf8_buf, utf8_len, &mbs);

		if (rc == (size_t)-1 || rc == (size_t)-2) {
			putchar(7);
			continue;
		}

		if (is_echo) {
			for (int j = 0; j < utf8_len; j++) {
				putchar((unsigned char)utf8_buf[j]);
			}
		}

		password[index] = wc;
		disp_width[index] = (uint8_t)utf8_len;
		index++;
	}

	printf("\n");
	print_warning(
		_("The max password input size is %i characters. No new input will be accepted. Consider key file instead."),
		MAX_PASSWORD_INPUT_LEN - 1);
	printf(_("press enter to proceed."));
	while (terminal_read_char() != '\n') {}
	password[MAX_PASSWORD_INPUT_LEN - 1] = 0;

END_EMPTY:
END:
	terminal_restore_echo();

	/* Easter egg check */
	{
		bool all_ascii = true;
		for (unsigned i = 0; i < index; i++) {
			if (password[i] > 0x7F) { all_ascii = false; break; }
		}
		if (all_ascii) {
			char tmp[MAX_PASSWORD_INPUT_LEN + 1];
			for (unsigned i = 0; i < index && i < MAX_PASSWORD_INPUT_LEN; i++) {
				tmp[i] = (char)password[i];
			}
			tmp[index] = 0;
			if (strcmp(tmp, "level-128") == 0) {
				print_error("👿");
			}
		}
	}

	return index;
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

char32_t *convert_key_to_unicode(const char *input, unsigned *out_len) {
	size_t input_len = strlen(input);
	char32_t *result = malloc((input_len + 1) * sizeof(char32_t));
	if (!result) {
		print_error(_("Memory allocation failed for key conversion"));
	}

	unsigned count = 0;
	mbstate_t mbs = {0};
	const char *p = input;

	while (*p) {
		char32_t wc = 0;
		size_t rc = mbrtoc32(&wc, p, MB_CUR_MAX, &mbs);

		if (rc == 0) break;
		if (rc == (size_t)-1 || rc == (size_t)-2) {
			print_error(_("Invalid multibyte sequence in --key argument"));
		}
		result[count++] = wc;
		p += rc;
	}
	result[count] = 0;
	*out_len = count;
	return result;
}
