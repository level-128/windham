#ifndef INCL_BKLIB_AUX
#define INCL_BKLIB_AUX

#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include "bklibkey.c"
#include "bksrclib.c"
#include "../include/windham_const.h"

#include "../libplat/get_entropy.c"
#include "../libplat/loopctl.c"
#include "../libsrc/probelib.c"



// Action: Add a new aux entry to the aux zone.
// aux_slot_key = ret_inited_key: derived key from keyslot, or zero for --master-key.
// input: raw multibyte string from command line, will be parsed to char32_t via parse_mb_to_char32.
void action_aux_add(
	const char * device,
	PARAMS_FOR_KEY,
	const char * input) {

	Data    data;
	int64_t offset;

	const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

	OPERATION_BACKEND_UNENCRYPT_HEADER

	size_t  aux_zone_size = 0;
	uint8_t * aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);

	if (aux_zone_size != 0) {
		if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
			print_error(_("Failed to decrypt aux zone. The header may be damaged."));
		}
	}

	if (aux_zone_size == 0) {
		print_error(_("This device does not have an aux zone."));
	}

	const uint8_t * aux_slot_key = ret_inited_key;

	char32_t * content = NULL;
	size_t content_size = 0;
	parse_mb_to_char32(input, &content, &content_size);

	if (!add_new_aux_to_aux_zone(aux_zone, aux_zone_size, aux_slot_key, content, content_size)) {
		print_error(_("Failed to add aux entry. The aux zone may be full."));
	}

	encrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key);
	write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
	OPERATION_LOCK_AND_WRITE
	free(aux_zone);
	free(content);
}


// Action: Add a shell-command aux entry to the aux zone.
// cmd: raw multibyte shell command string from command line.
// flag_str: flag string ("", "BLCKOPEN", "NOMASTER", "SHORTCUT").
void action_aux_add_command(
	const char * device,
	PARAMS_FOR_KEY,
	const char * cmd,
	const char * flag_str) {

	uint8_t flags = 0;
	if (!flag_str || flag_str[0] == '\0' || strcmp(flag_str, "BLCKOPEN") == 0) {
		flags |= AUX_CONTENT_SHELL_FLG_STOP_EXEC_NEXT_IF_SUCC;
	} else if (strcmp(flag_str, "SHORTCUT") == 0) {
		flags |= AUX_CONTENT_LINK_OPEN_FLG_STOP_EXEC_NEXT_IF_SUCC;
	} else {
		print_error(_("Unknown --flag value: %s. Valid: BLCKOPEN, SHORTCUT"), flag_str);
	}

	Data    data;
	int64_t offset;

	const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

	OPERATION_BACKEND_UNENCRYPT_HEADER

	size_t  aux_zone_size = 0;
	uint8_t * aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);

	if (aux_zone_size != 0) {
		if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
			print_error(_("Failed to decrypt aux zone. The header may be damaged."));
		}
	}

	if (aux_zone_size == 0) {
		print_error(_("This device does not have an aux zone."));
	}

	const uint8_t * aux_slot_key = ret_inited_key;

	char32_t * content = NULL;
	size_t content_size = 0;
	compose_shell_content(cmd, flags, 0, &content, &content_size);

	if (!add_new_aux_to_aux_zone(aux_zone, aux_zone_size, aux_slot_key, content, content_size)) {
		print_error(_("Failed to add aux entry. The aux zone may be full."));
	}

	encrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key);
	write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
	OPERATION_LOCK_AND_WRITE
	free(aux_zone);
	free(content);
}


// Action: Add a link-open aux entry. Probes the target path for its UUID,
// prompts for the target device's key, verifies it, and stores the key
// with its KDF iteration level in the aux zone.
void action_aux_add_link(
	const char * device,
	PARAMS_FOR_KEY,
	const char * link_path,
	const char * target_key_password,
	const char * target_keyfile_path,
	const char * link_flag_str,
	const char * link_prio_str) {

	// 1. Probe the link target for UUID
	uint8_t link_uuid[16];
	int probe_type;
	if (!probe_single_device(link_path, link_uuid, &probe_type)) {
		print_error(_("%s is not a Windham partition or encrypted device."), link_path);
	}

	// 2. Get the user's password in char32_t form (pre-hash)
	char32_t link_password[MAX_PASSWORD_INPUT_LEN];
	unsigned pw_count;
	bool dummy_unicode = false;
	if (target_key_password != NULL) {
		unsigned out_len = 0;
		char32_t *heap_pw = convert_key_to_unicode(target_key_password, &out_len);
		pw_count = out_len;
		if (pw_count > MAX_PASSWORD_INPUT_LEN) {
			pw_count = MAX_PASSWORD_INPUT_LEN;
		}
		memcpy(link_password, heap_pw, pw_count * sizeof(char32_t));
		free(heap_pw);
	} else if (target_keyfile_path != NULL) {
		FILE *fp = fopen(target_keyfile_path, "rb");
		if (fp == NULL) {
			print_error(_("Cannot open target key file %s: %s"), target_keyfile_path, strerror(errno));
		}
		if (fseek(fp, 0, SEEK_END) != 0) {
			print_error(_("Cannot seek target key file %s: %s"), target_keyfile_path, strerror(errno));
		}
		long fsize = ftell(fp);
		if (fsize < 0) {
			print_error(_("Cannot determine size of target key file %s: %s"), target_keyfile_path, strerror(errno));
		}
		rewind(fp);
		unsigned ccount = ((unsigned)fsize + 3) / 4;
		pw_count = ccount;
		if (pw_count > MAX_PASSWORD_INPUT_LEN) {
			pw_count = MAX_PASSWORD_INPUT_LEN;
		}
		uint8_t *fdata = malloc((size_t)fsize);
		if (fread(fdata, 1, (size_t)fsize, fp) != (size_t)fsize) {
			fclose(fp);
			free(fdata);
			print_error(_("Error reading target key file %s"), target_keyfile_path);
		}
		fclose(fp);
		for (unsigned i = 0; i < pw_count; i++) {
			char32_t val = 0;
			unsigned base = i * 4;
			if (base < (unsigned)fsize) val |= (char32_t)fdata[base] << 24;
			if (base + 1 < (unsigned)fsize) val |= (char32_t)fdata[base + 1] << 16;
			if (base + 2 < (unsigned)fsize) val |= (char32_t)fdata[base + 2] << 8;
			if (base + 3 < (unsigned)fsize) val |= (char32_t)fdata[base + 3];
			link_password[i] = val;
		}
		free(fdata);
	} else {
		printf(_("Password for linked device %s:\n"), link_path);
		pw_count = get_password_input(link_password, &dummy_unicode);
	}
	if (pw_count == 0) { print_error(_("Empty password.")); }

	// 3. Hash to inited_key for verification
	uint8_t link_inited_key[HASHLEN];
	password_to_sha256(link_password, pw_count, link_inited_key);

	// 4. Load header of the linked device
	Data link_data;
	int64_t link_offset;
	const ENUM_MAPPER_DEVSTAT lstat = load_header_by_device(link_path, &link_data, &link_offset, false, false);
	if (lstat != NMOBJ_MAPPER_DEVSTAT_NORM) {
		print_error(_("Cannot load header of linked device %s."), link_path);
	}

	// 5. Verify the password can unlock the linked device
	uint16_t loc = get_keypool_location_candidate(link_data.master_key_mask, link_inited_key);
	unsigned link_level, link_zone;
	uint8_t  link_master_key[HASHLEN];
	int unlock_ret = read_key_from_data(link_data, link_inited_key, loc,
	                                    max_unlock_time, max_unlock_mem,
	                                    max_unlock_level, is_allow_nolock,
	                                    &link_zone, &link_level, link_master_key);
	switch (unlock_ret) {
	case NMOBJ_Enclib_calc_failed_no_time:
	case NMOBJ_Enclib_calc_failed_level_exceeded:
	case NMOBJ_Enclib_calc_failed_reached_max_mem:
		print_error(_("Cannot unlock linked device %s — possibly incorrect key or insufficient time/memory."), link_path);
	default: break;
	}

	// 6. Open main device and unlock its aux zone
	Data data;
	int64_t offset;
	const ENUM_MAPPER_DEVSTAT st = load_header_by_device(device, &data, &offset, is_decoy, false);
	OPERATION_BACKEND_UNENCRYPT_HEADER

	size_t aux_zone_size = 0;
	uint8_t *aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);
	if (aux_zone_size != 0) {
		if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
			print_error(_("Failed to decrypt aux zone."));
		}
	}
	if (aux_zone_size == 0) {
		print_error(_("This device does not have an aux zone."));
	}

	// 7. Compose link-open content with the pre-hash char32_t password
	uint8_t link_flags = 0;
	if (link_flag_str != NULL && link_flag_str[0] != '\0') {
		if (strcmp(link_flag_str, "SHORTCUT") == 0) {
			link_flags = AUX_CONTENT_LINK_OPEN_FLG_STOP_EXEC_NEXT_IF_SUCC;
		} else {
			print_error(_("Unknown --link-flag value: %s. Valid: SHORTCUT"), link_flag_str);
		}
	}
	uint8_t link_prio = 128;
	if (link_prio_str != NULL && link_prio_str[0] != '\0') {
		long val = strtol(link_prio_str, NULL, 10);
		if (val < 0 || val > 255) {
			print_error(_("--link-prio must be between 0 and 255"));
		}
		link_prio = (uint8_t)val;
	}
	char32_t *content = NULL;
	size_t content_size = 0;
	compose_link_open_content(link_password, pw_count, link_flags, link_uuid,
	                          (int8_t)link_level, link_prio, &content, &content_size);

	const uint8_t *aux_slot_key = ret_inited_key;
	if (!add_new_aux_to_aux_zone(aux_zone, aux_zone_size, aux_slot_key, content, content_size)) {
		print_error(_("Failed to add aux entry. The aux zone may be full."));
	}

	encrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key);
	write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
	OPERATION_LOCK_AND_WRITE
	free(aux_zone);
	free(content);
}


// Action: Delete aux entries matching the derived key from the aux zone.
// aux_slot_key = ret_inited_key: derived key from keyslot, or zero for --master-key.
void action_aux_del(
	const char * device,
	PARAMS_FOR_KEY) {

	Data    data;
	int64_t offset;

	const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

	OPERATION_BACKEND_UNENCRYPT_HEADER

	// Read aux zone from device (metadata is now decrypted)
	size_t  aux_zone_size = 0;
	uint8_t * aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);

	if (aux_zone_size != 0) {
		if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
			print_error(_("Failed to decrypt aux zone. The header may be damaged."));
		}
	}

	// aux_slot_key is ret_inited_key: the derived key from keyslot, or zero for --master-key
	const uint8_t * aux_slot_key = ret_inited_key;

	if (aux_zone_size == 0) {
		print_error(_("This device does not have an aux zone."));
	}

	// Remove entries matching aux_slot_key
	remove_aux_from_aux_zone_by_key(aux_zone, aux_zone_size, aux_slot_key);

	// Re-encrypt aux zone, lock metadata, and write back
	encrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key);
	write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
	OPERATION_LOCK_AND_WRITE
	free(aux_zone);
}


// Action: Probe (list) aux entries from the aux zone.
// probe_aux_from_aux_zone simultaneously probes public (zero-key) entries
// and entries matching aux_slot_key.
// aux_slot_key = ret_inited_key: derived key from keyslot, or zero for --master-key.
void action_aux_probe(
	const char * device,
	PARAMS_FOR_KEY) {

	Data    data;
	int64_t offset;

	const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

	OPERATION_BACKEND_UNENCRYPT_HEADER

	// Read aux zone from device (metadata is now decrypted)
	size_t  aux_zone_size = 0;
	uint8_t * aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);

	if (aux_zone_size != 0) {
		if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
			print_error(_("Failed to decrypt aux zone. The header may be damaged."));
		}
	}

	// aux_slot_key is ret_inited_key: the derived key from keyslot, or zero for --master-key
	const uint8_t * aux_slot_key = ret_inited_key;

	if (aux_zone_size == 0) {
		printf(_("This device does not have an aux zone.\n"));
		return;
	}

	// probe_aux_from_aux_zone probes both public and key-derived entries
	int count = 0;
	uint32_t pointer = 0;

	while (true) {
		bool is_public = false;
		uint32_t slot_offset = 0;
		AuxSlot * slot = probe_aux_from_aux_zone(aux_zone, aux_zone_size, &pointer, aux_slot_key, &is_public, &slot_offset);
		if (slot == NULL) break;
		count++;
		uint8_t aux_type = ((uint8_t *)slot->content_char32_be)[0];
		if (aux_type == NMOBJ_AUX_TYPE_LINK_OPEN) {
			print_link_open_entry(slot, slot_offset, is_public, count);
		} else if (aux_type == NMOBJ_AUX_TYPE_SHELL) {
			print_shell_entry(slot, slot_offset, is_public, count);
		} else {
			print_aux_entry(slot, slot_offset, is_public, count);
		}
		free(slot);
	}

	if (count == 0) {
		printf(_("No aux entries found.\n"));
	} else {
		printf(_("Found %d aux entry(ies).\n"), count);
	}

	free(aux_zone);
}


// Delete a single aux entry by its 1-based probe index.
void action_aux_rm(
	const char * device,
	PARAMS_FOR_KEY,
	int index) {

	Data    data;
	int64_t offset;

	const ENUM_MAPPER_DEVSTAT device_stat = load_header_by_device(device, &data, &offset, is_decoy, false);

	OPERATION_BACKEND_UNENCRYPT_HEADER

	size_t  aux_zone_size = 0;
	uint8_t * aux_zone = read_aux_zone_from_device(device, &data, &aux_zone_size);

	if (aux_zone_size != 0) {
		if (!decrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key)) {
			print_error(_("Failed to decrypt aux zone. The header may be damaged."));
		}
	}

	if (aux_zone_size == 0) {
		print_error(_("This device does not have an aux zone."));
	}

	const uint8_t * aux_slot_key = ret_inited_key;

	if (!remove_single_aux_by_index(aux_zone, aux_zone_size, aux_slot_key, index)) {
		print_error(_("No aux entry found at index %d for the given key."), index);
	}

	encrypt_aux_zone_using_master_key(&data, aux_zone, aux_zone_size, master_key);
	write_aux_zone_to_device(device, &data, aux_zone, aux_zone_size);
	OPERATION_LOCK_AND_WRITE
	free(aux_zone);
}

#endif
