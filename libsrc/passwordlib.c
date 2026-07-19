/* Portable password input logic, shared by all platforms.
 *
 * The platform terminal primitives (terminal_disable_echo,
 * terminal_restore_echo, terminal_read_char) and the WINDHAM_TERM_RAW
 * macro are provided by libplat/<platform>/password_input.c, which is
 * included before this file by libplat/password_input.c.
 *
 * WINDHAM_TERM_RAW == 1: raw terminal -- echo suppressed, input delivered
 *   per keystroke, ANSI escape sequences available. Text mode offers the
 *   tab-to-echo prompt; unicode mode edits the current line in place.
 * WINDHAM_TERM_RAW == 0: canonical terminal -- input is line-buffered and
 *   echoed by the terminal itself. Text mode enters unicode mode with
 *   Space at empty input (the trailing newline of that line is consumed);
 *   unicode mode prints on new lines instead of in-place editing.
 */

#ifndef INCL_PASSWORDLIB
#define INCL_PASSWORDLIB

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifndef WINDHAM_TERM_RAW
#error "the platform password_input.c must define WINDHAM_TERM_RAW to 0 or 1"
#endif

#define MIN_KEY_CHAR 7

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

/* Print one password character. Returns the number of bytes written when
   the character was rendered as text (usable for backspace erasure), or 0
   when a "U+XXXXXXXX" placeholder was printed instead. */
static int print_password_char(char32_t c) {
#ifdef WINDHAM_UTF_32
	char utf8_out[8]; // MB_CUR_MAX <= 6, + 1 for NUL
	mbstate_t mbs = {0};
	size_t len = c32rtomb(utf8_out, c, &mbs);
	if (len != (size_t)-1) {
		utf8_out[len] = 0;
		printf("%s", utf8_out);
		return (int)len;
	}
	printf("U+%08X", (unsigned)c);
	return 0;
#else
	if (c <= 0x7F && c >= 0x20) {
		putchar((int)c);
		return 1;
	}
	printf("U+%08X", (unsigned)c);
	return 0;
#endif
}

unsigned get_password_input(char32_t password[MAX_PASSWORD_INPUT_LEN], bool *out_is_unicode) {
	terminal_disable_echo();
	*out_is_unicode = false;

#if WINDHAM_TERM_RAW
	bool is_echo = false;
	uint8_t disp_width[MAX_PASSWORD_INPUT_LEN];
#endif
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
#if WINDHAM_TERM_RAW
				printf(_(
					"Unicode mode: enter a Unicode code point as up to 8 hex digits after each \"U+\" prompt.\n"
					"  Press Enter on an empty line to display all characters (does not exit).\n"
					"  Enter \"0\" (U+0000) to finish without display.\n"
					"  Enter \"_\" to delete the previous character.\n"
					"  Press Backspace on an empty code point to delete the previous character.\n"));
#else
				printf(_(
					"Unicode mode: enter a Unicode code point as up to 8 hex digits after each \"U+\" prompt.\n"
					"  Press Enter on an empty line to display all characters (does not exit).\n"
					"  Enter \"0\" (U+0000) to finish without display.\n"
					"  Enter \"_\" to delete the previous character.\n"));
#endif
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
#if WINDHAM_TERM_RAW
						printf("\r\033[K");
#else
						printf("\n");
#endif
						if (index > 0) {
							for (unsigned i = 0; i < index; i++) {
								if (i > 0) printf(" ");
								print_password_char(password[i]);
							}
						} else {
							printf("%s", _("(no characters entered)"));
						}
#if WINDHAM_TERM_RAW
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
#else
						printf("\n");
						printf("%s", _("Press Enter to continue."));
						fflush(stdout);

						/* Wait for Enter (canonical mode: consume entire line) */
						while (terminal_read_char() != '\n') {}
						break;
#endif
					}

					/* Underscore: delete previous character */
					if (hex_len == 1 && hex_buf[0] == '_') {
						if (index > 0) {
							index--;
#if WINDHAM_TERM_RAW
							if (disp_width[index] > 0) {
								for (int k = 0; k < disp_width[index]; k++) {
									printf("\b \b");
								}
								printf("\b \b");
							}
#endif
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

					/* Display the character */
					printf(" ");
#ifdef WINDHAM_UTF_32
#if WINDHAM_TERM_RAW
					disp_width[index] = (uint8_t)print_password_char((char32_t)val);
#else
					print_password_char((char32_t)val);
#endif
#else
					printf("U+%08X", (unsigned)val);
#if WINDHAM_TERM_RAW
					disp_width[index] = 0;
#endif
#endif
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

#if WINDHAM_TERM_RAW
					/* hex buffer empty: move to previous line and overwrite */
					if (index > 0) {
						index--;
						printf("\033[A\r\033[K");
						printf("U+");
						fflush(stdout);
					} else {
						putchar(7);
					}
					continue;
#else
					/* hex buffer empty: delete previous character and announce */
					if (index > 0) {
						index--;
						printf("\n");
						printf("%s", _("Previous character deleted."));
					} else {
						putchar(7);
					}
					break;
#endif
				}

				if (ch == '_' && hex_len == 0) {
					hex_buf[0] = '_';
					hex_len = 1;
#if WINDHAM_TERM_RAW
					putchar('_');
#else
					printf("Previous character deleted.");
#endif
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
			/* inner while exited via break -- restart outer loop for next U+ */
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

#if WINDHAM_TERM_RAW
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
#else
		/* Canonical mode: Tab may not reach the program. Space at empty
		   input directly enters unicode mode as a fallback. */
		if (ch == ' ' && index == 0) {
			is_unicode = true;
			terminal_read_char(); /* consume trailing '\n' from canonical mode Enter */
			continue;
		}
#endif

		if (ch == '\x7f') {
			if (index == 0) {
				putchar(7);
				continue;
			}
			index--;
#if WINDHAM_TERM_RAW
			if (is_echo) {
				for (int k = 0; k < disp_width[index]; k++) {
					printf("\b \b");
				}
			}
#else
			printf("\b \b");
#endif
			continue;
		}

#ifdef WINDHAM_UTF_32
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

#if WINDHAM_TERM_RAW
		if (is_echo) {
			for (int j = 0; j < utf8_len; j++) {
				putchar((unsigned char)utf8_buf[j]);
			}
		}
		disp_width[index] = (uint8_t)utf8_len;
#endif
		password[index] = wc;
		index++;
#else
		/* WINDHAM_UTF_32 not defined: only accept ASCII */
		if ((unsigned char)ch > 0x7F) {
			print_error(
				_("Non-ASCII character detected. This ISO C platform does not define WINDHAM_UTF_32, "
				  "so multi-byte encodings cannot be handled reliably. "
				  "Use unicode mode instead: type Space then Enter at empty input."));
		}

#if WINDHAM_TERM_RAW
		if (is_echo) {
			putchar(ch);
		}
		disp_width[index] = 1;
#endif
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

char32_t *convert_key_to_unicode(const char *input, unsigned *out_len) {
#ifdef WINDHAM_UTF_32
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
				  "WINDHAM_UTF_32, so only ASCII passwords are supported via --key. "
				  "Use --key-file for arbitrary binary keys."));
		}
		result[count++] = (char32_t)(unsigned char)*p;
	}
	result[count] = 0;
	*out_len = count;
	return result;
#endif
}

#endif // #ifndef INCL_PASSWORDLIB
