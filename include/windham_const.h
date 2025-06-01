#ifndef WINDHAM_INCL_WINDHAM_CONST_H
#define WINDHAM_INCL_WINDHAM_CONST_H

#include <stdio.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>
#include <errno.h>

#include "aes.h"

#ifndef WINDHAM_VERSION
#define WINDHAM_VERSION "unknown"
#endif


/*
 * ---------- Define for ISO C compatibility ----------
*/

#ifndef CMAKE_VERSION
#define WINDHAM_ISOC
#endif

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
 * ---------- Define consts ----------
*/
// Some consts are defined in CMake, these are:
#ifndef DEFAULT_TARGET_TIME
#define DEFAULT_TARGET_TIME 1
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

#ifndef DEFAULT_DISK_ENC_MEM_RATIO_CAP
#define DEFAULT_DISK_ENC_MEM_RATIO_CAP 30
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
#ifndef WINDHAM_ISOC
#include <locale.h>
#include <libintl.h>
#include <termios.h>

#define _(STRING) gettext(STRING)
#else
#define _(STRING) STRING
#endif


// jump back to test when running unit test
#ifndef IS_FRONTEND_ENTRY
#warning "Test target"

#define _(STRING) STRING

jmp_buf exit_jmp;

// backup terminal config.
#elif !defined(WINDHAM_ISOC)
// backup terminal config when interacting
struct termios oldt;
// init process to exec when pid1
char * init_process;
#endif

// the original stdout fd
int stdout_fd;

// is running at pid1
bool is_pid1;
bool is_has_system_env;

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

/*
 * ---------- Define header format ----------
*/


uint8_t shebang_line[] = {'#', '/', 's', 'b', 'i', 'n', '/', 'w', 'i', 'n', 'd', 'h', 'a',
        'm', ' ', 'O', 'p', 'e', 'n', '\n'};

uint8_t windham_head[32] = {'w', 'i', 'n', 'd', 'h', 'a', 'm'};

uint8_t windham_hint_head[14] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25};


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

  // reserved for future use
  alignas(1) uint8_t                         _metadata_unused_plain[64];

  // additional entropy for converting master key to disk key.
  alignas(1) uint8_t                         disk_key_mask[HASHLEN];

  // contents after WINDHAM_METADATA_ENC_BORDER remains encrypted after suspend.
#define WINDHAM_METADATA_ENC_BORDER keyslot_key

  // registered key stored after initial hash. These keys can be used to reencrypt the header.
  //
  alignas(AES_BLOCKLEN) uint8_t                         keyslot_key[KEY_SLOT_COUNT][HASHLEN];
  alignas(1) uint8_t                         keyslot_level[KEY_SLOT_COUNT];
  alignas(2) uint16_t                        keyslot_location[KEY_SLOT_COUNT];
  alignas(8) uint64_t                        keyslot_location_area;
  alignas(8) uint64_t                        check_key_magic_number;
} EncMetadata;


typedef struct {
  alignas(1) uint8_t key_mask[HASHLEN]; // 256b
  alignas(1) uint8_t hash_salt[HASHLEN]; // 256b
  alignas(4) uint8_t len_exp[KEY_SLOT_EXP_MAX][4]; // 32b each
} Key_slot;

// salt size for KDF per level
#define cal_salt_size(level_minus_one) HASHLEN + 4 * ((level_minus_one) + 1)


typedef struct {
  alignas(1) uint8_t max_level;
  alignas(1) uint8_t header_type;
} Hint;


typedef uint8_t Keypool[KEY_SLOT_COUNT * sizeof(Key_slot) * 4];

typedef struct STR_data {
  alignas(1) uint8_t                         head[30];
  alignas(1) Hint                            hint;

  // UUID, also as salt to prevent tempering
  alignas(1) uint8_t                         uuid_and_salt[16];

  // Unique mask (or vector if you prefer) of which the memery per KDF step, metadata encryption depends on.
  alignas(1) uint8_t                         master_key_mask[HASHLEN];

  // first 128b of sha256(master_key_mask) enc with master_key
  alignas(1) uint8_t                         master_key_check[AES_BLOCKLEN];

  // metadata area. Padding to AES blocklen for encryption.
  alignas(AES_BLOCKLEN) EncMetadata          metadata;

  alignas(AES_BLOCKLEN) struct {
    alignas(1) Keypool                       keypool;
    alignas(4) Key_slot                      WINDHAM_ATTRIBUTE(unused) _keypool_padding;
  }                                          keypool[2];

  // offset: 19472
} Data; //

#define convert_stage_to_size(stage) HASHLEN + HASHLEN + 4u * (stage)
#define get_slot_loc(_data, keypool_idx, keypool_loc) ((Key_slot *)&_data.keypool[keypool_idx].keypool[keypool_loc])
#define RAW_HEADER_AREA_IN_SECTOR (( sizeof(Data) + 511) / 512)
#define HEADER_AREA_IN_SECTOR ((RAW_HEADER_AREA_IN_SECTOR + 7) / 8) * 8
#define WINDHAM_FIRST_USEABLE_LGA (((RAW_HEADER_AREA_IN_SECTOR + 1) + 7) / 8) * 8

#endif