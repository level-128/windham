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


/**
 * @brief Adds a key to the Linux Keyring service.
 *
 * This function adds a key to the Linux Keyring service. The key is added only if
 * certain conditions are satisfied, such as the block size, encryption mode, and
 * start sector being equal to specific default values. If the key is successfully
 * added to the keyring, a timeout value is set for the key as well.
 *
 * @param key The key to be added, given as an array of bytes.
 * @param uuid The generated UUID for the key, represented as an array of bytes.
 * @param metadata The metadata information for the key.
 * @param timeout The timeout value for the key.
 *
 * @return None.
 */
void mapper_keyring_add_key(const uint8_t key[HASHLEN], uint8_t uuid[16], EncMetadata metadata, unsigned timeout) {
	
	if (!is_kernel_keyring_exist) {
		return;
	}
	bool is_ok_for_keyring = true;
	
	if (metadata.block_size == DEFAULT_BLOCK_SIZE){
		print_warning(_("Cannot register the key into Linux Keyring service: The block size is not equal to the default value (%u), got (%u)."), DEFAULT_BLOCK_SIZE, metadata.block_size);
		is_ok_for_keyring = false;
	}
	if (strcmp(metadata.enc_type, DEFAULT_DISK_ENC_MODE) != 0){
		print_warning(_("Cannot register the key into Linux Keyring service: The encryption mode is not the same as the default (%s), got (%s). The default encryption mode may varies between "
							 "architecture."), DEFAULT_DISK_ENC_MODE, metadata.enc_type);
		is_ok_for_keyring = false;
	} if (metadata.start_sector != 8){
		print_warning(_("Cannot register the key into Linux Keyring service: The start sector is not the same as the default value (%u), got (%lu)."), 8, metadata.start_sector);
		is_ok_for_keyring = false;
	}

	if (is_ok_for_keyring) {
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
	}
}

/**
 * @brief Retrieves the serial number of a key from the keyring.
 *
 * This function returns the serial number of a key identified by the given UUID. It performs the following steps:
 * 1. Checks if the kernel keyring exists. If it does not exist, it returns NMOBJ_KEY_ERR_KERNEL_KEYRING.
 * 2. Generates a key name by concatenating the string "windham:" with the UUID converted to a string.
 * 3. Calls the p_keyctl function to search for the key in the user keyring with the name "logon" and the generated key name.
 * 4. If the key is not found, it returns NMOBJ_KEY_ERR_NOKEY.
 * 5. If the key is revoked, it attempts to unlink it from the user keyring. It then returns NMOBJ_KEY_ERR_KEYREVOKED.
 * 6. If the key has expired, it unlinks it from the user keyring and returns NMOBJ_KEY_ERR_KEYEXPIRED.
 * 7. If an error occurs during the key search, it prints an error message and exits with status 1.
 * 8. If the key is found, it returns NMOBJ_KEY_OK.
 *
 * @param[in] uuid The UUID of the key.
 * @return The serial number of the key or an error code if the key is not found or an error occurs.
 */
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