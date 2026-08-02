// Include all libraries if build system not present.
#ifdef WINDHAM_PLAT_GNU_LINUX
#error "GNU/Linux should use cmake to include all libs"
#endif

// Map compiler thread-disabled state to Argon2's no-threads macro.
// CMake handles this via -D; direct compiles need the fallback.
#if defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)
#ifndef ARGON2_NO_THREADS
#define ARGON2_NO_THREADS
#endif
#endif

#ifndef __Argon2_opt_disable__
#define __Argon2_opt_disable__
#endif

// because all t=1, no thread needed.
#define ARGON2_NO_THREADS

#include "Argon2/argon2.c"
#include "Argon2/core.c"
#include "Argon2/ref.c"
#include "Argon2/encoding.c"
#include "Argon2/blake2/blake2b.c"

// cJSON only used by GNU/Linux

// getopt_port
#include "getopt_port/getopt.c"

// huffman
// skip all huffman code.
#ifndef CFG_NO_ENTROPY_DETECTION

#include "huffman/huffman.c"

#endif

// QRCode
#include "QRCode/QRCode.c"

// SHA256
#include "SHA256/sha256.c"

// tiny_AES.c
#include "tiny_AES_c/aes.c"

#ifndef CFG_DRIVER_NO_FF
#include "FatFs/ff.c"
#include "FatFs/ffunicode.c"
#include "FatFs/ffsystem.c"
#include "FatFs/ff_diskio.c"
#endif