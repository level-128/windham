#ifndef INCL_PASSWORD_INPUT
#define INCL_PASSWORD_INPUT

#include <stdint.h>
#include <uchar.h>

#define MAX_PASSWORD_INPUT_LEN 256

#ifndef WINDHAM_UTF_32
typedef uint_least32_t char32_t;
#endif

/* ── Public API ─────────────────────────────────────────────── */

unsigned get_password_input(char32_t password[MAX_PASSWORD_INPUT_LEN], bool *out_is_unicode);

unsigned get_key_input_from_the_console_systemd(const char *device, char32_t password[MAX_PASSWORD_INPUT_LEN]);

char32_t *convert_key_to_unicode(const char *input, unsigned *out_len);

/* ── Platform primitives (defined by the platform file below) ──
 *
 * Each platform must provide:
 *   #define WINDHAM_TERM_RAW  0 or 1
 *   static void terminal_disable_echo(void)
 *   static void terminal_restore_echo(void)
 *   static int  terminal_read_char(void)
 *
 * and may optionally provide:
 *   unsigned get_key_input_from_the_console_systemd(...)
 */

#ifdef WINDHAM_PLAT_WASI
#include "WASI/password_input.c"
#elif defined(WINDHAM_PLAT_GNU_LINUX)
#include "GNU_Linux/password_input.c"
#else
#include "ISOC/password_input.c"
#endif

/* ── Shared implementation (uses the primitives above) ──────── */
#include "../libsrc/passwordlib.c"

#endif
