// Include all libraries if build system not present.
#ifdef WINDHAM_ISOC




#define ARGON2_NO_THREADS

#define __Argon2_opt_disable__

#include "Argon2/argon2.c"
#include "Argon2/core.c"
#include "Argon2/ref.c"
#include "Argon2/encoding.c"
#include "Argon2/blake2/blake2b.c"

// cJSON
#include "cJSON/cJSON.c"

// getopt_port
#include "getopt_port/getopt.c"

// huffman
#include "huffman/huffman.c"

// QRCode
#include "QRCode/QRCode.c"

// SHA256
#include "SHA256/sha256.c"

// tiny_AES.c
#include "tiny_AES_c/aes.c"


#include "FatFs/ff.c"
#include "FatFs/ffunicode.c"
#include "FatFs/ffsystem.c"
#include "FatFs/ff_diskio.c"

#endif