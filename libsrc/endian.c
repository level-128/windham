#ifndef INCL_ENDIAN
#define INCL_ENDIAN

#ifdef WINDHAM_PLAT_GNU_LINUX
#include <endian.h>
#else


#include <stdint.h>
#include <limits.h>

#define WINDHAM_LITTLE_ENDIAN 1234
#define WINDHAM_BIG_ENDIAN    4321


#if (CHAR_BIT != 8)
    #error "Sorry: Windham only supports system with 8-bit char."
#endif

#if (INT_MIN != -INT_MAX - 1)
   #error "Windham only supports system that repersents signed integer with 2's complement. "\
          "ISO C prior to C23 allows system to use 1's complement and sign-and-magnitude, however"\
          "Windham does not support these systems."
#endif

#if (__STDC_VERSION__ >= 202311L)
    #if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__
        #define BYTE_ORDER WINDHAM_LITTLE_ENDIAN
    #elif __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_BIG__
        #define BYTE_ORDER WINDHAM_BIG_ENDIAN
    #else
        #error "Unknown / Unsupport system byte order. Byte order must be either Big or Small. Running on PDP systems?"
    #endif

#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define BYTE_ORDER WINDHAM_LITTLE_ENDIAN
  #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define BYTE_ORDER WINDHAM_BIG_ENDIAN
  #else
    #error "Unknown / Unsupport system byte order. Byte order must be either Big or Small. Running on PDP systems?"
  #endif

// fallback to runtime if compilier does not provide runtime endianess
#else
  static int get_byte_order(void) {
      union {
          uint32_t i;
          unsigned char c[4];
      } test = {0x01020304};
      return (test.c[0] == 0x01) ? WINDHAM_BIG_ENDIAN : WINDHAM_LITTLE_ENDIAN;
  }
#endif

static inline uint16_t swap16(uint16_t x) {
    return (uint16_t)((x << 8) | (x >> 8));
}

static inline uint32_t swap32(uint32_t x) {
    return ((x << 24) & 0xff000000) |
           ((x <<  8) & 0x00ff0000) |
           ((x >>  8) & 0x0000ff00) |
           ((x >> 24) & 0x000000ff);
}

static inline uint64_t swap64(uint64_t x) {
    return ((x << 56) & 0xff00000000000000ULL) |
           ((x << 40) & 0x00ff000000000000ULL) |
           ((x << 24) & 0x0000ff0000000000ULL) |
           ((x <<  8) & 0x000000ff00000000ULL) |
           ((x >>  8) & 0x00000000ff000000ULL) |
           ((x >> 24) & 0x0000000000ff0000ULL) |
           ((x >> 40) & 0x000000000000ff00ULL) |
           ((x >> 56) & 0x00000000000000ffULL);
}

#if defined(BYTE_ORDER)
  #if BYTE_ORDER == WINDHAM_LITTLE_ENDIAN
    #define htobe16(x) swap16(x)
    #define htole16(x) (x)
    #define be16toh(x) swap16(x)
    #define le16toh(x) (x)

    #define htobe32(x) swap32(x)
    #define htole32(x) (x)
    #define be32toh(x) swap32(x)
    #define le32toh(x) (x)

    #define htobe64(x) swap64(x)
    #define htole64(x) (x)
    #define be64toh(x) swap64(x)
    #define le64toh(x) (x)
  #elif BYTE_ORDER == WINDHAM_BIG_ENDIAN
    #define htobe16(x) (x)
    #define htole16(x) swap16(x)
    #define be16toh(x) (x)
    #define le16toh(x) swap16(x)

    #define htobe32(x) (x)
    #define htole32(x) swap32(x)
    #define be32toh(x) (x)
    #define le32toh(x) swap32(x)

    #define htobe64(x) (x)
    #define htole64(x) swap64(x)
    #define be64toh(x) (x)
    #define le64toh(x) swap64(x)
  #endif
#else
  static inline uint16_t htobe16(uint16_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? swap16(x) : x;
  }
  static inline uint16_t htole16(uint16_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? x : swap16(x);
  }
  static inline uint16_t be16toh(uint16_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? swap16(x) : x;
  }
  static inline uint16_t le16toh(uint16_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? x : swap16(x);
  }

  static inline uint32_t htobe32(uint32_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? swap32(x) : x;
  }
  static inline uint32_t htole32(uint32_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? x : swap32(x);
  }
  static inline uint32_t be32toh(uint32_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? swap32(x) : x;
  }
  static inline uint32_t le32toh(uint32_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? x : swap32(x);
  }

  static inline uint64_t htobe64(uint64_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? swap64(x) : x;
  }
  static inline uint64_t htole64(uint64_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? x : swap64(x);
  }
  static inline uint64_t be64toh(uint64_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? swap64(x) : x;
  }
  static inline uint64_t le64toh(uint64_t x) {
      return (get_byte_order() == WINDHAM_LITTLE_ENDIAN) ? x : swap64(x);
  }
#endif

#endif
#endif
