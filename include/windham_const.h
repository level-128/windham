#pragma once

#include <fcntl.h>
#include <linux/limits.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>

#include "aes.h"

#if !defined(__GNUC__)
#warning "Unknown compilier."
#endif

#define VERSION "1.20241231.0"

// defined const
// Some consts are defined in CMake, these are:
#ifndef DEFAULT_TARGET_TIME
#define DEFAULT_TARGET_TIME 1
#endif

#define KEY_SLOT_COUNT 16

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

#ifndef CONFIG_WINDHAMTAB_FILE
#define CONFIG_WINDHAMTAB_FILE "/etc/windhamtab"
#endif
// end defined const.

//
#define HASHLEN 32

#define KEY_SLOT_EXP_MAX 20
#if KEY_SLOT_EXP_MAX % 4 != 0
#error "KEY_SLOT_EXP_MAX must devideable by 4, ensuring Key_slot is AES blocksize alligned."
#endif


#define BASE_MEM_COST 64
#define PARALLELISM 1

#define LOCATION_CANDIDATE_COUNT 2

// encryption related
#define CHECK_KEY_MAGIC_NUMBER 0x49713d1c7f5dce80U

// the original stdout fd
int stdout_fd;

// is running at pid1
bool is_pid1;

void windham_exit(int exitno);

// only used for test framework.
#ifndef IS_FRONTEND_ENTRY
#warning "Test target"
jmp_buf exit_jmp;
#else
// backup terminal config when interacting
struct termios oldt;
// init process to exec when pid1
char * init_process;
#endif

typedef struct {
  char name[PATH_MAX];
  long block_count;
  int  block_size;
  bool is_loop;
} Device;


Device *STR_device;

#define convert_stage_to_size(stage) HASHLEN + HASHLEN + 4 * (stage)

// Header def

#define WINDHAM_METADATA_VERSION 1

typedef struct __attribute__((packed)) {
  uint8_t                         disk_key_mask[HASHLEN];
  uint64_t                        start_sector;
  uint64_t                        end_sector; // in sector
  char                            enc_type[29];
  uint8_t                         metadata_version;
  uint16_t                        block_size;

  // remains encrypted after suspend
  uint8_t                         keyslot_key[KEY_SLOT_COUNT][HASHLEN];
  uint8_t                         keyslot_level[KEY_SLOT_COUNT];
  uint16_t                        keyslot_location[KEY_SLOT_COUNT];
  uint64_t                        keyslot_location_area;
  uint64_t                        check_key_magic_number;
} EncMetadata;



typedef struct __attribute__((packed)) {
  uint8_t key_mask[HASHLEN]; // 256b
  uint8_t hash_salt[HASHLEN]; // 256b
  uint8_t len_exp[KEY_SLOT_EXP_MAX][4]; // 32b each
} Key_slot;
#define cal_salt_size(level_minus_one) HASHLEN + 4 * ((level_minus_one) + 1)


uint8_t hint_head[12] = {'h', 'i', 'n', 't', 'h', 'i', 'n', 't', 'h', 'i', 'n', 't'};

typedef struct __attribute__((packed)) {
  uint8_t hint_head[12];
  uint8_t min_level;
  uint8_t max_level;
  uint8_t local_level_cap;
  uint8_t flags;
} Hint;

enum {
  NMOBJ_header_hint_is_extended_keypool_payload,
  NMOBJ_header_hint_is_no_pw_registered

};


typedef uint8_t Keypool[KEY_SLOT_COUNT * sizeof(Key_slot) * 5];
typedef struct __attribute__((packed)) STR_data {
  uint8_t                         head[16];
  uint8_t                         uuid_and_salt[16];
  uint8_t __attribute__((unused)) _unused[32];
  uint8_t                         master_key_mask[HASHLEN];
  uint8_t                         master_key_check[AES_BLOCKLEN]; // first 128b of sha256(master_key_mask) enc with master_key
  EncMetadata                     metadata;
  uint8_t __attribute__((unused)) _metadata_aes_padding[sizeof(EncMetadata) % AES_BLOCKLEN];
  struct __attribute__((packed)) {
    Keypool                       keypool;
    Key_slot                       __attribute__((unused)) _keypool_padding;
  }                                keypool[2];
} Data;

#define get_slot_loc(_data, keypool_idx, keypool_loc) ((Key_slot *)&_data.keypool[keypool_idx].keypool[keypool_loc])
#define RAW_HEADER_AREA_IN_SECTOR  (sizeof(Data) / 512 + (sizeof(Data) % 512 != 0))
#define HEADER_AREA_IN_SECTOR ((RAW_HEADER_AREA_IN_SECTOR + 7) / 8) * 8
#define WINDHAM_FIRST_USEABLE_LGA (((RAW_HEADER_AREA_IN_SECTOR + 1) + 7) / 8) * 8

