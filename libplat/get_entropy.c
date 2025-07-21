#ifndef INCL_GET_ENTROPY
#define INCL_GET_ENTROPY

#include <stdint.h>
#include <stddef.h>


void fill_secure_random_bits(uint8_t * address, const size_t size);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/get_entropy.c"
#else
#include "ISOC/get_entropy.c"
#endif

#endif