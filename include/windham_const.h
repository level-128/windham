#ifndef INCL_WINDHAM_CONST_H
#define INCL_WINDHAM_CONST_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "aes.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "This code cannot be compiled on a big-endian machine."
#endif

#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif

#define VERSION "0.231128.1.1"

// defined const
#define HASHLEN 32

#define KEY_SLOT_COUNT 6
#define KEY_SLOT_EXP_MAX 20
#define BASE_MEM_COST 64
#define PARALLELISM 1
#define DEFAULT_ENC_TARGET_TIME 1
#define DEFAULT_DISK_ENC_MODE "aes-xts-plain64"
#define DEFAULT_TARGET_TIME 1
#define MAX_UNLOCK_TIME_FACTOR 5
#define DEFAULT_BLOCK_SIZE 4096
#define DEFAULT_SECTION_SIZE 16 * 1024 * 1024

// encryption related
#define CHECK_KEY_MAGIC_NUMBER 0x49713d1c7f5dce80

FILE * random_fd; // file handler of the random number generator.

typedef struct __attribute__((packed)) {
	uint8_t disk_key_mask[HASHLEN];
	uint64_t start_sector;
	uint64_t end_sector;  // in sector
	char enc_type[32];
	uint16_t block_size;
	__attribute__((unused)) uint8_t padding[AES_BLOCKLEN - sizeof(uint16_t)];
	
	// remains encrypted after suspend
	uint8_t keyslot_key[KEY_SLOT_COUNT][HASHLEN];
	uint8_t all_key_mask[KEY_SLOT_COUNT][HASHLEN];
	int8_t key_slot_is_used[KEY_SLOT_COUNT];
	__attribute__((unused)) uint8_t reserved[34];
	uint64_t check_key_magic_number;
} EncMetadata;

#endif