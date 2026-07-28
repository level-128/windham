/* ASCII-only uchar replacement for CFG_ASCII mode.
 *
 * When CFG_ASCII is defined, WINDHAM_UTF_16 and WINDHAM_UTF_32 are
 * masked out (see windham_const.h).  This file provides typedefs and
 * stub implementations for the C11 uchar API that the codebase uses,
 * so that <uchar.h> is never needed.
 *
 * Include this file instead of <uchar.h> at every include site,
 * using a path relative to the file doing the inclusion:
 *
 *     libsrc/auxlib.c           → #include "ucar.c"
 *     include/ff.h              → #include "../libsrc/ucar.c"
 *     libplat/password_input.c  → #include "../libsrc/ucar.c"
 *     backend/bklibkey.c        → #include "../libsrc/ucar.c"
 *     library/FatFs/ffunicode.c → #include "../../libsrc/ucar.c"
 *
 * Always wrapped in a CFG_ASCII check:
 *
 * The file is named "ucar.c" (not "uchar.c") to avoid collision
 * with a real <uchar.h> header that might be present in the source
 * tree (e.g. musl libc vendored into the repository).  Since the
 * include path contains both libsrc/ and the system headers, a file
 * named "uchar.c" could shadow <uchar.h> when the CFG_ASCII check
 * is absent, producing a silent wrong-include.  "ucar.c" cannot be
 * confused with any standard header.
 *
 * All conversion functions accept only ASCII (0x00-0x7F); non-ASCII
 * input returns (size_t)-1 (encoding error).
 */

#ifdef CFG_ASCII
#ifndef WINDHAM_UCHAR_ASCII_H
#define WINDHAM_UCHAR_ASCII_H

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

/* C11 uchar typedefs (same as <uchar.h>).  While the surrounding code
 * may already typedef these when WINDHAM_UTF_32/WINDHAM_UTF_16 are
 * absent, C11 permits identical redeclarations of the same type. */
typedef uint_least16_t char16_t;
typedef uint_least32_t char32_t;

/* --- c16rtomb --- write one char16_t as a multibyte sequence ----- */
static inline size_t c16rtomb(char *restrict s, char16_t c16,
                              mbstate_t *restrict ps)
{
    (void)ps;
    if (s == NULL) return 1;
    if (c16 <= 0x7F) { *s = (char)c16; return 1; }
    return (size_t)-1;
}

/* --- mbrtoc16 --- read one multibyte character into char16_t ------ */
static inline size_t mbrtoc16(char16_t *restrict pc16,
                              const char *restrict s, size_t n,
                              mbstate_t *restrict ps)
{
    (void)ps;
    if (s == NULL) return mbrtoc16(pc16, "", 1, ps);
    if (n == 0) return (size_t)-2;
    unsigned char c = (unsigned char)*s;
    if (c <= 0x7F) {
        if (pc16) *pc16 = c;
        return 1;
    }
    return (size_t)-1;
}

/* --- c32rtomb --- write one char32_t as a multibyte sequence ----- */
static inline size_t c32rtomb(char *restrict s, char32_t c32,
                              mbstate_t *restrict ps)
{
    (void)ps;
    if (s == NULL) return 1;
    if (c32 <= 0x7F) { *s = (char)c32; return 1; }
    return (size_t)-1;
}

/* --- mbrtoc32 --- read one multibyte character into char32_t ------ */
static inline size_t mbrtoc32(char32_t *restrict pc32,
                              const char *restrict s, size_t n,
                              mbstate_t *restrict ps)
{
    (void)ps;
    if (s == NULL) return mbrtoc32(pc32, "", 1, ps);
    if (n == 0) return (size_t)-2;
    unsigned char c = (unsigned char)*s;
    if (c <= 0x7F) {
        if (pc32) *pc32 = c;
        return 1;
    }
    return (size_t)-1;
}

#endif /* WINDHAM_UCHAR_ASCII_H */
#endif /* CFG_ASCII */
