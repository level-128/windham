#ifndef INCL_WINDHAM_CONST_H
#define INCL_WINDHAM_CONST_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdnoreturn.h>
#include <libintl.h>
#include <setjmp.h>

#include "aes.h"

#ifndef UINT8_MAX
#error "the program only supports platform with uint8_t defined"
#endif

#define VERSION "0.231128.3.0"

#define _(STRING) gettext(STRING)

// defined const
#define HASHLEN 32

#define KEY_SLOT_COUNT 6
#define KEY_SLOT_EXP_MAX 20
#define BASE_MEM_COST 64
#define PARALLELISM 1
#define DEFAULT_ENC_TARGET_TIME 1
#define DEFAULT_TARGET_TIME 1
#define MAX_UNLOCK_TIME_FACTOR 5
#define DEFAULT_BLOCK_SIZE 4096
#define DEFAULT_SECTION_SIZE 16 * 1024 * 1024

#ifndef DEFAULT_DISK_ENC_MODE
#define DEFAULT_DISK_ENC_MODE "aes-xts-plain64"
#endif

// encryption related
#define CHECK_KEY_MAGIC_NUMBER 0x49713d1c7f5dce80U

FILE * random_fd; // file handler of the random number generator.

jmp_buf windham_exit;

enum {
	NMOBJ_windham_exit_normal = 1,
	NMOBJ_windham_exit_error = 2,
};


typedef struct{
   const char * name;
	size_t block_size;
   bool is_malloced_name;
   bool is_loop;
} Device;

Device * STR_device;

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
	uint32_t section_size;
	__attribute__((unused)) uint8_t reserved[30];
	uint64_t check_key_magic_number;
} EncMetadata;

typedef struct __attribute__((packed)) {
	uint8_t hash_salt[HASHLEN]; // 256b
	uint8_t len_exp[KEY_SLOT_EXP_MAX][4]; // 32b each
	uint8_t key_mask[HASHLEN]; // 256b
} Key_slot;

typedef struct __attribute__((packed)) STR_data {
	uint8_t head[16];
	uint8_t uuid_and_salt[16];
	uint8_t master_key_mask[HASHLEN];
	Key_slot keyslots[KEY_SLOT_COUNT];
	EncMetadata metadata;
	__attribute__((unused)) uint8_t AES_align[
			(AES_BLOCKLEN - (sizeof(EncMetadata) % AES_BLOCKLEN)) % AES_BLOCKLEN];
} Data;

#endif