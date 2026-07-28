// uchar.h stub for platforms that lack C11 uchar.h (e.g. macOS).
// Provides typedefs and minimal stubs for mbrtoc16 / c16rtomb needed
// by FatFs ffunicode.c; return 0 (no conversion) when unsupported.
#ifndef WINDHAM_UCHAR_STUB_H
#define WINDHAM_UCHAR_STUB_H

#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

typedef uint_least16_t char16_t;
typedef uint_least32_t char32_t;

static inline size_t c16rtomb(char *restrict s, char16_t c16, mbstate_t *restrict ps) {
    (void)ps;
    if (s == NULL) return 1;
    // Narrow path: only ASCII (0x00-0x7F) is supported.
    if (c16 <= 0x7F) { *s = (char)c16; return 1; }
    return (size_t)-1;
}

static inline size_t mbrtoc16(char16_t *restrict pc16, const char *restrict s,
                              size_t n, mbstate_t *restrict ps) {
    (void)ps;
    if (s == NULL) return mbrtoc16(pc16, "", 1, ps);
    if (n == 0) return (size_t)-2;
    // Narrow path: only ASCII is supported.
    unsigned char c = (unsigned char)*s;
    if (c <= 0x7F) {
        if (pc16) *pc16 = c;
        return 1;
    }
    return (size_t)-1;
}

static inline size_t c32rtomb(char *restrict s, char32_t c32, mbstate_t *restrict ps) {
    (void)ps;
    if (s == NULL) return 1;
    if (c32 <= 0x7F) { *s = (char)c32; return 1; }
    return (size_t)-1;
}

static inline size_t mbrtoc32(char32_t *restrict pc32, const char *restrict s,
                              size_t n, mbstate_t *restrict ps) {
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

#endif
