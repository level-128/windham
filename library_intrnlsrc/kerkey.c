#include "windham_const.h"

#include <dlfcn.h>

#include <libdevmapper.h>
#include <keyutils.h>

#include "srclib.c"

bool is_kernel_keyring_exist;

// data
#ifndef INCL_KERKEY
#define INCL_KERKEY

typeof(add_key) * p_add_key;
typeof(keyctl_set_timeout) * p_keyctl_set_timeout;
typeof(keyctl) * p_keyctl;
typeof(keyctl_unlink) * p_keyctl_unlink;

#pragma GCC poison add_key keyctl_set_timeout keyctl_read keyctl_unlink keyctl

typedef enum {
	NMOBJ_KEY_OK = 0,
	NMOBJ_KEY_ERR_NOKEY = -1,
	NMOBJ_KEY_ERR_KEYREVOKED = -2,
	NMOBJ_KEY_ERR_KEYEXPIRED = -3,
	NMOBJ_KEY_ERR_KERNEL_KEYRING = -4
} ENUM_mp_key;

void kernel_keyring_init(){
		void * handle = dlopen("libkeyutils.so", RTLD_LAZY);
		if (!handle) {
			print_warning(_("Linux Kernel Keyring subsystem support is missing. Security is deduced, and some features (\"--timeout\") might not be supported. "
								 "Kernel keyring is not required but strongly recommended."));
			is_kernel_keyring_exist = false;
		} else {
			is_kernel_keyring_exist = true;
			p_add_key = dlsym(handle, "add_key");
			p_keyctl_set_timeout = dlsym(handle, "keyctl_set_timeout");
			p_keyctl = dlsym(handle, "keyctl");
			p_keyctl_unlink = dlsym(handle, "keyctl_unlink");
		}
}


int mapper_keyring_add_key(const uint8_t key[HASHLEN], uint8_t uuid[16], EncMetadata metadata, unsigned timeout) {
	
	if (!is_kernel_keyring_exist) {
		return 0;
	}
	char not_equal[100] = "{";
	if (metadata.block_size == DEFAULT_BLOCK_SIZE){
		strcat(not_equal, "block size, ");
	}
	if (strcmp(metadata.enc_type, DEFAULT_DISK_ENC_MODE) != 0){
		strcat(not_equal, "encryption mode, ");
	}
	strcat(not_equal, "}");
	if (strcmp(not_equal, "{}") != 0){
		print_warning(_("Cannot store the key into Linux Keyring service, reason: %s is not equal to the default value. Use command \"windham help\" to see a list of default values."), not_equal);
	}
	
	char name[strlen("windham:") + 36 /* uuid len */ + 1];
	strcpy(name, "windham:");
	generate_UUID_from_bytes(uuid, name + strlen("windham:"));
	
	key_serial_t key_serial;
	key_serial = p_add_key("logon", name, key, HASHLEN, KEY_SPEC_USER_KEYRING);
	
	if (key_serial < 0) {
		perror("add_key");
		exit(1);
	}
	p_keyctl_set_timeout(key_serial, timeout);
	
	return 0;
}

ENUM_mp_key mapper_keyring_get_serial(uint8_t uuid[16]) {
	key_serial_t key_serial;
	if (!is_kernel_keyring_exist) {
		return NMOBJ_KEY_ERR_KERNEL_KEYRING;
	}
	char name[strlen("windham:") + 36 /* uuid len */ + 1];
	strcpy(name, "windham:");
	generate_UUID_from_bytes(uuid, name + strlen("windham:"));
	
	key_serial = (key_serial_t) p_keyctl(KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, "logon", name, NULL, 0);
	if (key_serial < 0) {
		if (errno == ENOKEY) {
			return NMOBJ_KEY_ERR_NOKEY;
		} else if (errno == EKEYREVOKED) {
			p_keyctl_unlink(KEY_SPEC_USER_KEYRING, key_serial); // try to clear this, might fail but don't care
			return NMOBJ_KEY_ERR_KEYREVOKED;
		} else if (errno == EKEYEXPIRED) {
			p_keyctl_unlink(KEY_SPEC_USER_KEYRING, key_serial);
			return NMOBJ_KEY_ERR_KEYEXPIRED;
		}
		perror("request_key");
		exit(1);
	}
	return NMOBJ_KEY_OK;
}

#endif