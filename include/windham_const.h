#ifndef WINDHAM_INCL_WINDHAM_CONST_H
#define WINDHAM_INCL_WINDHAM_CONST_H

#include <stdio.h>
#ifndef WINDHAM_PLAT_WASI
#include <setjmp.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "aes.h"

#ifndef WINDHAM_VERSION
#define WINDHAM_VERSION "unknown"
#endif

#ifndef CMAKE_TARGET_ARCH
#define CMAKE_TARGET_ARCH "unknown"
#endif
#ifndef CMAKE_HOST_ARCH
#define CMAKE_HOST_ARCH "unknown"
#endif
#ifndef CMAKE_BUILD_TIME
#define CMAKE_BUILD_TIME "unknown"
#endif


/*
 * ---------- Platform detection ----------
 * ISOC is the baseline — platforms opt in for extra features via CMake.
 * Non-CMake builds default to ISOC baseline (no platform macro defined).
 */

#if (__STDC_VERSION__ >= 202311L)
#define WINDHAM_ATTRIBUTE(x) [[x]] // attribute syntax in C23
#define WINDHAM_UNREACHABLE unreachable();
#elif defined(__GNUC__)
#define WINDHAM_ATTRIBUTE(x) __attribute__((x)) // attribute syntax in GCC / Clang
#define WINDHAM_UNREACHABLE __builtin_unreachable();
#define maybe_unused unused
#else
#define WINDHAM_ATTRIBUTE(x)
#define WINDHAM_UNREACHABLE \
  assert(("unreachable code reached", false)); \
  exit(2);
#endif


/*
 * ---------- UTF-16 / UTF-32 support ----------
 * When CFG_ASCII is defined, both are masked out (ASCII-only fallback).
 */

#ifdef CFG_ASCII
// WINDHAM_UTF_16 and WINDHAM_UTF_32 are intentionally left undefined
#else
#ifdef __STDC_UTF_16__
#define WINDHAM_UTF_16
#endif
#ifdef __STDC_UTF_32__
#define WINDHAM_UTF_32
#endif
#endif


/*
 * ---------- Define consts ----------
 */
// Some consts are defined in CMake, these are:
#ifndef CFG_DEFAULT_DRIVER
#define CFG_DEFAULT_DRIVER "ff"
#endif
#ifndef DEFAULT_TARGET_TIME
#define DEFAULT_TARGET_TIME 1.5
#endif

#ifndef MAX_UNLOCK_TIME_FACTOR
#define MAX_UNLOCK_TIME_FACTOR 5
#endif

#ifndef DEFAULT_BLOCK_SIZE
#define DEFAULT_BLOCK_SIZE 4096
#endif

#ifndef DEFAULT_DISK_ENC_MODE
#define DEFAULT_DISK_ENC_MODE "aes-xts-plain64"
#endif

#ifndef DEFAULT_DISK_KEY_SIZE_BYTES
#define DEFAULT_DISK_KEY_SIZE_BYTES 64  // AES-256-XTS: 32 data + 32 tweak
#endif

#ifndef DEFAULT_DISK_ENC_MEM_RATIO_CAP
#define DEFAULT_DISK_ENC_MEM_RATIO_CAP 30
#endif

#ifndef DEFAULT_AUX_SECTOR_SIZE
#define DEFAULT_AUX_SECTOR_SIZE 16
#endif

#ifndef DEFAULT_MIN_MEMLOCK_SIZE
#define DEFAULT_MIN_MEMLOCK_SIZE 1024 * 1024 * 8
#endif

#ifndef WINDHAMTAB_FILE
#define WINDHAMTAB_FILE "/etc/windhamtab"
#endif

#ifndef ARGON2_CLEAR_INTERNAL_MEMORY
#define ARGON2_CLEAR_INTERNAL_MEMORY 0
#endif

#if defined(CFG_FF_CREATE) && !defined(CFG_DRIVER_FF)
#error "CFG_FF_CREATE requires CFG_DRIVER_FF to be enabled"
#endif


// those are constants, not defined by cmake
#define KEY_SLOT_COUNT 16
#define HASHLEN 32
#define KEY_SLOT_EXP_MAX 20
#define BASE_MEM_COST 64
#define PARALLELISM 1
#define LOCATION_CANDIDATE_COUNT 2

#define CHECK_KEY_MAGIC_NUMBER 0x49713d1c7f5dce80U

/*
 * ---------- Define common structs and data ----------
*/

// GNU gettext
#ifdef WINDHAM_PLAT_GNU_LINUX
#include <locale.h>
#include <libintl.h>
#include <termios.h>

#define _(STRING) gettext(STRING)
#else
#define _(STRING) STRING
#endif

#ifndef WINDHAM_CONST_HEADER_ONLY

// Library mode (not frontend entry): strip gettext, provide exit_jmp
#ifndef IS_FRONTEND_ENTRY
#define _(STRING) STRING
jmp_buf exit_jmp;
#endif

// backup terminal config
#if defined(IS_FRONTEND_ENTRY) && defined(WINDHAM_PLAT_GNU_LINUX)
struct termios oldt;
#endif

// the original stdout fd
int stdout_fd;

void windham_exit(int exitno);


// struct for describe the device after init_device.
typedef struct {
  char name[FILENAME_MAX + 1];
  int64_t block_count; // -1 means unknown
  int  block_size; // -1 means unknown
  bool is_loop;
  bool is_block;
} Device;


Device *STR_device;


// struct for describing platform information
typedef struct {
    bool is_secure_env; // no auto exec aux shell
    bool is_shebang; // only windham Open <device> supported.
    bool is_color_print; // enable output color.
    enum {
        EMOBJ_RANDOM_NUMBER_SYSTEM, // ISOC mode with unix /dev/urandom, or Linux mode.
        EMOBJ_RANDOM_NUMBER_INTERNAL, // generating entropy use clock and process speed.
        EMOBJ_RANDOM_NUMBER_WEAK, // no reliable source for generating random number.
    } is_random_number_trustworthy;
    struct { // no need if RANDOM_NUMBER_SYSTEM
        clock_t clock;
        struct timespec time;
    } initial_internal_entropy_source;
    unsigned char extra_contents[];
} PlatInitVal;

// if there is a frontend, then the platform information is givin by the frontend.
#ifdef IS_FRONTEND_ENTRY
PlatInitVal * init_val;
#else
// default init without frontend.
PlatInitVal * init_val = &((PlatInitVal){
  .is_secure_env = false,
  .is_shebang = false,
  .is_color_print = false,
  .is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_SYSTEM,
  .initial_internal_entropy_source.clock = 0,
  .initial_internal_entropy_source.time.tv_nsec=0,
  .initial_internal_entropy_source.time.tv_sec=0,
});

#pragma message("PlatInitVal fallback to default. You might need to initialize this.")

#endif
/*
 * ---------- Define header format ----------
*/


uint8_t shebang_line[16] = {'#', '!', '/', 'b', 'i', 'n', '/', 'w', 'i', 'n', 'd', 'h', 'a',
        'm', '\n', 0};

uint8_t suspend_hint_tag[16] = {128, 128, 128, 128, 128, 128, 128, 128, 128, 's', 'u', 's', 'p', 'e', 'n', 'd'};


// External Partition software should write this. Windham will ignore this head.
uint8_t windham_partition_magic[16] = {'w', 'i', 'n', 'd', 'h', 'a', 'm', 'l', 'e', 'v',
   'e', 'l', '-', '1', '2', '8'};

#endif // WINDHAM_CONST_HEADER_ONLY


// Metadata struct
typedef struct {
  // metadata version.
  alignas(1) uint8_t                         metadata_version;
#define WINDHAM_METADATA_VERSION 1

  // encryption type in plaintext.
  alignas(1) char                            enc_type[29];

  // encryption block size.
  alignas(2) uint16_t                        block_size;

  // start and end sector. sector = bytes / 512.
  alignas(8) uint64_t                        start_sector;
  alignas(8) uint64_t                        end_sector;

  // start and end of the auxiliary sector. sector = bytes / 512.
  alignas(8) uint64_t                        start_aux_sector;
  alignas(1) uint8_t                         aux_sector_size;

  alignas(1) uint8_t                         disk_key_size_in_bits_div_64;

  // reserved for future use
  alignas(1) uint8_t                         _metadata_unused_plain[54];

  // additional entropy for converting master key to disk key.
  alignas(1) uint8_t                         disk_key_mask[HASHLEN];

  // contents after WINDHAM_METADATA_ENC_BORDER remains encrypted after suspend.
#define WINDHAM_METADATA_ENC_BORDER keyslot_key

  // registered key stored after initial hash. These keys can be used to reencrypt the header.
  //
  alignas(AES_BLOCKLEN) uint8_t              keyslot_key[KEY_SLOT_COUNT][HASHLEN];
  alignas(1) uint8_t                         keyslot_level[KEY_SLOT_COUNT];
  alignas(2) uint16_t                        keyslot_location[KEY_SLOT_COUNT];
  alignas(8) uint64_t                        keyslot_location_area;
  alignas(1) uint8_t                         aux_key_mask[HASHLEN];
  alignas(8) uint64_t                        check_key_magic_number;
} EncMetadata;

static_assert(sizeof(EncMetadata) == 752, "size of EncMetadata mismatch under your platform. "
                                          "An non ISO C conformation compiler? "
                                          "Before MSVC 2022 version 17.10, if the alignas specifier appeared next to a "
                                          "structured type in a declaration, it wasn't applied correctly according to "
                                          "the ISO C standard.");


typedef struct {
  alignas(1) uint8_t key_mask[HASHLEN]; // 256b
  alignas(1) uint8_t hash_salt[HASHLEN]; // 256b
  alignas(4) uint8_t len_exp[KEY_SLOT_EXP_MAX][4]; // 32b each
} Key_slot;

// salt size for KDF per level
#define cal_salt_size(level_minus_one) HASHLEN + 4 * ((level_minus_one) + 1)


typedef union {
  alignas(1) uint8_t windham_partition_magic_area[16]; // random by default. 
  alignas(1) struct {
    alignas(1) uint8_t hint_tag[14];
    alignas(1) int8_t max_iter_level;
    alignas(1) uint8_t flags;
  } hint;
} Hint;


typedef uint8_t Keypool[KEY_SLOT_COUNT * sizeof(Key_slot) * 4];

typedef struct STR_data {
  alignas(1) uint8_t                         head[16];
  alignas(1) Hint                            hint;

  // UUID, also as salt to prevent tempering
  alignas(AES_BLOCKLEN) uint8_t                         uuid_and_salt[16];

  // Unique mask (or vector if you prefer) of which the memory per KDF step, metadata encryption depends on.
  // IVs for AES CBC
  alignas(AES_BLOCKLEN) uint8_t                         master_key_mask[HASHLEN];

  // first 128b of sha256(master_key_mask) enc with master_key
  alignas(AES_BLOCKLEN) uint8_t                         master_key_check[AES_BLOCKLEN];

  // metadata area. Padding to AES blocklen for encryption.
  alignas(AES_BLOCKLEN) EncMetadata          metadata;

  alignas(AES_BLOCKLEN) struct {
    alignas(1) Keypool                       keypool;
    alignas(4) Key_slot                      _keypool_padding;
  }                                          keypool[2];

  // offset: 19536
} Data; //

static_assert(sizeof(Data) == 19568, "size of Data mismatch under your platform. An non ISO C conformation compiler?");

#define convert_stage_to_size(stage) (HASHLEN + HASHLEN + 4u * (stage))
#define get_slot_loc(_data, keypool_idx, keypool_loc) ((Key_slot *)&_data.keypool[keypool_idx].keypool[keypool_loc])
#define RAW_HEADER_AREA_IN_SECTOR (( sizeof(Data) + 511) / 512)
#define HEADER_AREA_IN_SECTOR (((RAW_HEADER_AREA_IN_SECTOR + 7) / 8) * 8)
#define WINDHAM_FIRST_USEABLE_LGA(aux_size) (((HEADER_AREA_IN_SECTOR + ((aux_size + 511) / 512) + 7) / 8) * 8)

#endif