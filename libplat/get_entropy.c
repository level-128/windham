#ifndef INCL_GET_ENTROPY
#define INCL_GET_ENTROPY

#include <stdint.h>
#include <stddef.h>


void fill_secure_random_bits(uint8_t * address, const size_t size);

#ifdef WINDHAM_PLAT_WASI
#include "WASI/get_entropy.c"
#elif defined(WINDHAM_PLAT_GNU_LINUX)
#include "GNU_Linux/get_entropy.c"
#else
#include "ISOC/get_entropy.c"
#endif

#endif