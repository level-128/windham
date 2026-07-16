#ifndef INCL_PASSWORD_INPUT
#define INCL_PASSWORD_INPUT

#include <stdint.h>
#include <uchar.h>

#define MAX_PASSWORD_INPUT_LEN 256

#ifndef WINDHAM_UTF_32
typedef uint_least32_t char32_t;
#endif

unsigned get_password_input(char32_t password[MAX_PASSWORD_INPUT_LEN], bool *out_is_unicode);

unsigned get_key_input_from_the_console_systemd(const char *device, char32_t password[MAX_PASSWORD_INPUT_LEN]);

char32_t *convert_key_to_unicode(const char *input, unsigned *out_len);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/password_input.c"
#else
#include "ISOC/password_input.c"
#endif

#endif
