#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MIN_KEY_CHAR 7

#ifndef __STDC_UTF_32__
static bool stdin_is_unbuffered = false;
#endif

static void terminal_disable_echo(void) {
}

static void terminal_restore_echo(void) {
}

static int terminal_read_char(void) {
#ifndef __STDC_UTF_32__
	if (!stdin_is_unbuffered) {
		setvbuf(stdin, NULL, _IONBF, 0);
		stdin_is_unbuffered = true;
	}
#endif
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
	*out_is_unicode = false;

	bool is_unicode = false;
	unsigned index = 0;
	bool unicode_help_shown = false;

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
					"  Enter \"_\" to delete the previous character.\n"));
			}

			printf("\nU+");
			fflush(stdout);

			char hex_buf[9] = {0};
			int hex_len = 0;

			while (1) {
				int ch = terminal_read_char();

				if (ch == '\n') {
					if (hex_len == 0) {
						/* Empty line: display all characters, then resume */
						printf("\n");
						if (index > 0) {
#ifdef __STDC_UTF_32__
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
#else
							for (unsigned i = 0; i < index; i++) {
								if (i > 0) printf(" ");
								if (password[i] <= 0x7F && password[i] >= 0x20) {
									putchar((unsigned)password[i]);
								} else {
									printf("U+%08X", (unsigned)password[i]);
								}
							}
#endif
						} else {
							printf("%s", _("(no characters entered)"));
						}
						printf("\n");
						printf("%s", _("Press Enter to continue."));
						fflush(stdout);

						/* Wait for Enter (canonical mode: consume entire line) */
						int c;
						while ((c = terminal_read_char()) != '\n') {}
						break;
					}

					/* Underscore: delete previous character */
					if (hex_len == 1 && hex_buf[0] == '_') {
						if (index > 0) {
							index--;
						}
						break;
					}

					/* Parse hex value */
					hex_buf[hex_len] = 0;
					char *endptr;
					unsigned long val = strtoul(hex_buf, &endptr, 16);
					if (*endptr != 0 || val > 0x10FFFF) {
						putchar(7);
						break;
					}

					if (val == 0) {
						printf("\n");
						goto END;
					}

					password[index] = (char32_t)val;

					/* Display the character */
					printf(" ");
#ifdef __STDC_UTF_32__
					char utf8_out[MB_CUR_MAX + 1];
					mbstate_t mbs = {0};
					size_t len = c32rtomb(utf8_out, (char32_t)val, &mbs);
					if (len != (size_t)-1) {
						utf8_out[len] = 0;
						printf("%s", utf8_out);
					} else {
						printf("U+%08X", (unsigned)val);
					}
#else
					printf("U+%08X", (unsigned)val);
#endif
					putchar(' ');

					index++;
					break;
				}

				if (ch == '\x7f') { /* backspace */
					if (hex_len > 0) {
						hex_len--;
						printf("\b \b");
						continue;
					}

					/* hex buffer empty: delete previous character and announce */
					if (index > 0) {
						index--;
						printf("\n");
						printf("%s", _("Previous character deleted."));
					} else {
						putchar(7);
					}
					break;
				}

				if (ch == '_' && hex_len == 0) {
					hex_buf[0] = '_';
					hex_len = 1;
					printf("Previous character deleted.");
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

		/* ISOC canonical mode: on Linux, Tab key may not reach the program.
		   Space at empty input directly enters unicode mode as a fallback. */
		if (ch == ' ' && index == 0) {
			is_unicode = true;
			terminal_read_char(); /* consume trailing '\n' from canonical mode Enter */
			continue;
		}

		if (ch == '\x7f') {
			if (index == 0) {
				putchar(7);
				continue;
			}
			index--;
			printf("\b \b");
			continue;
		}

#ifdef __STDC_UTF_32__
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

		password[index] = wc;
		index++;
#else
		/* __STDC_UTF_32__ not defined: only accept ASCII */
		if ((unsigned char)ch > 0x7F) {
			print_error(
				_("Non-ASCII character detected. This ISO C platform does not define __STDC_UTF_32__, "
				  "so multi-byte encodings cannot be handled reliably. "
				  "Use unicode mode instead: type Space then Enter at empty input."));
		}

		password[index] = (char32_t)(unsigned char)ch;
		index++;
#endif
	}

	printf("\n");
	print_warning(
		_("The max password input size is %i characters. No new input will be accepted. Consider key file instead."),
		MAX_PASSWORD_INPUT_LEN - 1);
	printf(_("press enter to proceed."));
	while (terminal_read_char() != '\n') {}
	password[MAX_PASSWORD_INPUT_LEN - 1] = 0;

END:
	terminal_restore_echo();

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

unsigned get_key_input_from_the_console_systemd(const char *WINDHAM_ATTRIBUTE(maybe_unused) device,
                                                 char32_t password[MAX_PASSWORD_INPUT_LEN]) {
	(void)password;
	print_error(_("\"--systemd-dialog\" is not available under ISO C. Use --key, --key-file, or interactive input instead."));
	return 0;
}

char32_t *convert_key_to_unicode(const char *input, unsigned *out_len) {
#ifdef __STDC_UTF_32__
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
#else
	size_t input_len = strlen(input);
	char32_t *result = malloc((input_len + 1) * sizeof(char32_t));
	if (!result) {
		print_error(_("Memory allocation failed for key conversion"));
	}

	unsigned count = 0;
	for (const char *p = input; *p; p++) {
		if ((unsigned char)*p > 0x7F) {
			free(result);
			print_error(
				_("Non-ASCII character in --key argument. This ISO C platform does not define "
				  "__STDC_UTF_32__, so only ASCII passwords are supported via --key. "
				  "Use --key-file for arbitrary binary keys."));
		}
		result[count++] = (char32_t)(unsigned char)*p;
	}
	result[count] = 0;
	*out_len = count;
	return result;
#endif
}
