#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdnoreturn.h>
#include <float.h>

#include <libintl.h>
#include <locale.h>


#define _(STRING) gettext(STRING)

#define VERSION "0.231118.0.0"
#define DEFAULT_EXEC_DIR "/etc/windham"

#include "enclib.c"
#include "backend.c"

enum {
	NMOBJ_to,
	NMOBJ_key,
	NMOBJ_key_file,
	NMOBJ_master_key,
	NMOBJ_target_slot,
	NMOBJ_unlock_slot,
	NMOBJ_max_unlock_mem,
	NMOBJ_max_unlock_time,
	NMOBJ_target_mem, //AddKey only
	NMOBJ_target_time, //AddKey only
	NMOBJ_encrypt_type,
	NMOBJ_block_size,
	
	NMOBJ_target_all,
	NMOBJ_target_obliterate,
	NMOBJ_target_dry_run,
	NMOBJ_target_no_transform,
	NMOBJ_target_restore,
	NMOBJ_target_decoy,
	NMOBJ_target_readonly,
	NMOBJ_target_allow_discards,
	NMOBJ_target_no_read_workqueue,
	NMOBJ_target_no_write_workqueue,
	NMOBJ_is_systemd,
	NMOBJ_is_nofail,
	NMOBJ_is_noadmin,
	NMOBJ_yes,
	
	NMOBJ_target_SIZE,
};

const char * const actions[] = {"Help", "Open", "Close", "New", "AddKey", "RevokeKey", "Backup", "Restore", "Suspend", "Resume"};
int options[NMOBJ_target_SIZE] = {0};

const struct option long_options[] = {
		{"to",                 required_argument, &options[NMOBJ_to],                        1},
		{"key",                required_argument, &options[NMOBJ_key],                       1},
		{"key-file",           required_argument, &options[NMOBJ_key_file],                  1},
		{"master-key",         required_argument, &options[NMOBJ_master_key],                1},
		{"target-slot",        required_argument, &options[NMOBJ_target_slot],               1},
		{"unlock-slot",        required_argument, &options[NMOBJ_unlock_slot],               1},
		{"max-unlock-memory",  required_argument, &options[NMOBJ_max_unlock_mem],            1},
		{"max-unlock-time",    required_argument, &options[NMOBJ_max_unlock_time],           1},
		{"target-memory",      required_argument, &options[NMOBJ_target_mem],                1},
		{"target-time",        required_argument, &options[NMOBJ_target_time],               1},
		{"encrypt-type",       required_argument, &options[NMOBJ_encrypt_type],              1},
		{"block-size",         required_argument, &options[NMOBJ_block_size],                1},
		
		{"all",                no_argument,       &options[NMOBJ_target_all],                1},
		{"obliterate",         no_argument,       &options[NMOBJ_target_obliterate],         1},
		{"dry-run",            no_argument,       &options[NMOBJ_target_dry_run],            1},
		{"no-transform",       no_argument,       &options[NMOBJ_target_no_transform],       1},
		{"restore",            no_argument,       &options[NMOBJ_target_restore],            1},
		{"decoy",              no_argument,       &options[NMOBJ_target_decoy],              1},
		{"readonly",           no_argument,       &options[NMOBJ_target_readonly],           1},
		{"allow-discards",     no_argument,       &options[NMOBJ_target_allow_discards],     1},
		{"no-read-workqueue",  no_argument,       &options[NMOBJ_target_no_read_workqueue],  1},
		{"no-write-workqueue", no_argument,       &options[NMOBJ_target_no_write_workqueue], 1},
		{"systemd-dialog",     no_argument,       &options[NMOBJ_is_systemd],                1},
		{"nofail",             no_argument,       &options[NMOBJ_is_nofail],                 1},
		{"no-admin",           no_argument,       &options[NMOBJ_is_noadmin],                1},
		{"yes",                no_argument,       &options[NMOBJ_yes],                       1},
		{0, 0,                                    0,                                         0}
};

#define CHECK_ALLOWED_OPEN NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_unlock_slot, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_target_decoy, NMOBJ_is_systemd, NMOBJ_is_nofail
#define CHECK_COMMON NMOBJ_is_noadmin, NMOBJ_yes

const int8_t check_allowed[] =
		// Open
		{CHECK_ALLOWED_OPEN, NMOBJ_to, NMOBJ_target_readonly, NMOBJ_target_dry_run, NMOBJ_target_allow_discards, NMOBJ_target_no_read_workqueue, NMOBJ_target_no_write_workqueue, CHECK_COMMON, -1,
				// Close
       CHECK_COMMON, -1,
				// New
       NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_target_slot, NMOBJ_target_mem, NMOBJ_target_time, NMOBJ_encrypt_type, NMOBJ_target_decoy, NMOBJ_block_size, CHECK_COMMON, -1,
				// AddKey
       CHECK_ALLOWED_OPEN, NMOBJ_max_unlock_time, NMOBJ_target_mem, NMOBJ_target_time, CHECK_COMMON, -1,
				// RevokeKey
       CHECK_ALLOWED_OPEN, NMOBJ_target_slot, NMOBJ_target_all, NMOBJ_target_obliterate, CHECK_COMMON, -1,
				// Backup
       CHECK_ALLOWED_OPEN, NMOBJ_to, NMOBJ_target_no_transform, CHECK_COMMON, -1,
				// Restore
       NMOBJ_to, CHECK_COMMON, -1,
				// Suspend
       CHECK_ALLOWED_OPEN, CHECK_COMMON, -1,
				// Resume
       CHECK_ALLOWED_OPEN, CHECK_COMMON, -1};


int frontend_check_actions(char * input) {
	for (int i = 0; (size_t) i < sizeof(actions) / sizeof(char *); i++) {
		if (strcmp(actions[i], input) == 0) {
			return i - 1; // help will return -1
		}
	}
	if (memcmp(input, "--", 2) == 0) {
		print_error(_("Arguments should locate after <action> and <target>."));
	}
	print_error(_("<action> not recognized. type 'windham Help' to view help"));
	return -1;
}

void frontend_check_invalid_param(int action_num) {
	int cnt = 0;
	for (int i = 0; (size_t) i < sizeof(actions) / sizeof(char *); i++) {
		if (i == action_num) {
			goto CHECK_ACTION_ARGS;
		}
		for (; check_allowed[cnt] != -1; cnt++) {}
		cnt++;
	}
	
	CHECK_ACTION_ARGS:
	for (int i = 0; i < NMOBJ_target_SIZE; i++) {
		if (options[i] == 1) {
			int j;
			for (j = cnt; check_allowed[j] != -1; j++) {
				if (check_allowed[j] == i) {
					break;
				}
			}
			if (check_allowed[j] == -1) {
				print_error(_("argument: %s is not valid under action: %s"), (char *) long_options[i].name, (char *) actions[action_num + 1]);
			}
		}
	}
}

void frontend_print_unlock_args() {
	printf(_(
			       "\nUnlock options:\n"
			       "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
			       "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' and '--target-slot' are mutually exclusive\n"
			       "\t--master-key <characters>: using master key to unlock.\n"
			       "\t--unlock-slot <int>: choose the slot to unlock; Other slots are ignored.\n"
			       "\t--max-unlock-memory <int>: total maximum available memory (KiB) available for decryption. \n"
			       "\t--max-unlock-time <float>: the suggested max time (sec) for unlock.\n"
			       "\t--systemd-dialog: use systemd password input dialog; useful when integrating with systemd.\n"));
};

void frontend_print_common_args() {
	printf(_(
			       "\nCommon options:\n"
			       "\t--no-admin: forfeit checking root privileges, may produces undefined behaviour. \n"
			       "\t--yes: do not ask for explicit conformation to potential destructive operations.\n"));
};

noreturn void frontend_help(const char * the_3rd_argv) {
	if (!the_3rd_argv) {
		printf(_("usage: \"windham <action> <target>\"\n"
		         "possible actions are:  'Open'  'Close'  'New'  'AddKey'  'RevokeKey' 'Backup' 'Restore' 'Suspend' and 'Resume'\n\n"
		         "Type \"windham Help <action>\" to view specific help text for each action.\n\n"
		         "pre-compiled arguments. These arguments serve an informative purpose; changing them may render your "
		         "device inaccessible.\n"));
		printf(_("number of keyslots: %i\n"), KEY_SLOT_COUNT);
		printf(_("Length of the hash (bit): %i\n"), HASHLEN * CHAR_BIT);
		printf(_("Argon2id memory size exponential count: %i\n"), KEY_SLOT_EXP_MAX);
		printf(_("Argon2id base memory size (KiB): %i\n"), BASE_MEM_COST);
		printf(_("Argon2id parallelism: %i\n"), PARALLELISM);
		printf(_("Default encryption target time: %i\n"), DEFAULT_ENC_TARGET_TIME);
		printf(_("Default decryption target time (per slot): %i\n"), MAX_UNLOCK_TIME_FACTOR);
		printf(_("Default encryption type: %s\n"), DEFAULT_DISK_ENC_MODE);
#ifdef __GNUC__
		printf(_("Compiler: GCC %d.%d.%d\n"), __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
		printf(_("Compile time: %s, %s"), __DATE__, __TIME__);
#endif
	} else if (strcmp("--license", the_3rd_argv) == 0) {
		printf(_("    Copyright (C) 2023-  W. Wang (level-128)\n"
		         "\n"
		         "    This program is free software: you can redistribute it and/or modify\n"
		         "    it under the terms of the GNU General Public License (version 3) as\n"
		         "    published by the Free Software Foundation.\n"
		         "\n"
		         "    This program is distributed in the hope that it will be useful,\n"
		         "    but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		         "    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
		         "    GNU General Public License for more details.\n"
		         "\n"
		         "    You should have received a copy of the GNU General Public License\n"
		         "    along with this program.  If not, see <https://www.gnu.org/licenses/>.\n"));
		printf(_("\n\tThere is also an \"Additional permissions\" applied from Article (7) when using, propagating and conveying the unmodified covered work. This \"additional "
		         "permissions\" is legal binding, which grants additional permissions to the licensee. See license.md for details."));
		
	} else if (strcmp(actions[1], the_3rd_argv) == 0) {
		printf(_("Open <target>: Unlock <target> and create a mapper (decrypted crypt device) under /dev/mapper/<location>. The key, by default, is read from the terminal.\n"
		         "\n"
		         "options:\n"
		         "\t--to <location>: REQUIRED; the target location of the mapper. The mapper will be named as <location>, locate under /dev/mapper/<location>\n"
		         "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"
		         "\t--dry-run: run without operating on the block device then print the master key and device parameters.\n"
		         "\t--readonly: Set the mapper device to read-only.\n"
					"\t--allow-discards: Allow TRIM command being sent to the crypt device.\n"
					"\t--no-read-workqueue: Process read requests synchronously instead of using a internal workqueue.\n"
					"\t--no-write-workqueue: Process write requests synchronously instead of using a internal workqueue.\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp(actions[2], the_3rd_argv) == 0) {
		printf(_("Close <target> close the encrypt block device.\n"));
		frontend_print_common_args();
		
	} else if (strcmp(actions[3], the_3rd_argv) == 0) {
		printf(_("New <target>: create a windham header on the device and add a new key. DO NOT COPY THE HEADER FROM OTHER ENCRYPTED DEVICES, BECAUSE THEY "
		         "COULD BE UNLOCKED USING THE SAME MASTER KEY. \n"
		         "\n"
		         "options:\n"
		         "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
		         "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' are mutually exclusive\n"
		         "\t--target-slot <int>: choose the target slot to add a new key; the first empty slot will be chosen as default.\n"
		         "\t--target-memory <int>: total maximum memory (KiB) available to use. \n"
		         "\t--target-time <float>: the suggested total time (sec) for adding the first key. This is not a hard limit.\n"
		         "\t--encrypt-type <string>: designate an encryption scheme for the new header instead of the default one. It is not recommended, nor necessary, to do so, unless"
		         " you have a specific reason. the encryption scheme should obey the format: \"*cipher*-*chainmode*-*ivmode*\".\n"
					"\t--block-size <int>: designate the encryption sector size. Size must be 512, 1024, 2048 or 4096.\n"
		         "\t--decoy: Create a decoy FAT32 partition. The encrypted partition stores at the unallocated sector of the FAT32 filesystem.\n"));
		frontend_print_common_args();
		printf(_("A list of supported encryption mode on your system is located at file \"/proc/crypto\". If the designated encryption scheme contains an unsupported, "
		         "but valid, mode, which will trigger a warning, the partition cannot be opened using your system.\n"));
		
	} else if (strcmp(actions[4], the_3rd_argv) == 0) {
		printf(_("AddKey <target>: Add a new key to the existing windham header. The new key will be asked after a successful unlock from the given key.\n"
		         "\n"
		         "options:\n"
		         "\t--target-memory <int>: The total maximum memory (KiB) available to use. \n"
		         "\t--target-time <float>: the suggested total time (sec) for adding a key. This is not a hard limit.\n"
		         "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp(actions[5], the_3rd_argv) == 0) {
		printf(_("RevokeKey <target>: remove a existing key from the header.\n"
		         "\n"
		         "options:\n"
		         "\t--target-slot <int>: revoke the key inside the target slot. No password required.\n"
		         "\t--all: revoke all slots; the device is inaccessible unless using master key to unlock.\n"
		         "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"
		         "\t--obliterate: Wipe the header and destroy all data."));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp(actions[6], the_3rd_argv) == 0) {
		printf(_("Backup <target>: Backup the header into a separate file.\n"
		         "\n"
		         "options:\n"
		         "\t--to <location>: REQUIRED; the location of the file.\n"
		         "\t--no-transform: backup the header as is. No key required. \n"
		         "\t--restore: restore the header from a backup file.\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp(actions[7], the_3rd_argv) == 0) {
		printf(_("Restore <target>: Restore the header from a file to the device.\n"
		         "\n"
		         "options:\n"
		         "\t--to <location>: REQUIRED; the location of the file.\n"));
		
	} else if (strcmp(actions[8], the_3rd_argv) == 0) {
		printf(_("Suspend <target>: Make device identifiable and accessible without password. When Suspending, only 'Close' and 'RevokeKey' (With param '--all', '--obliterate' and "
		         "'--target-slot') could be used.\n"
		         "\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp(actions[9], the_3rd_argv) == 0) {
		printf(_("Resume <target>: unsuspend the device.\n"
		         "\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
	} else {
		print_error("<action> not recognized. type 'windham Help' to view help");
	}
	exit(0);
}

noreturn void frontend_no_input() {
	printf(_("Windham (%s) Copyright (C) 2023-  W. Wang (level-128)\n\n"
	         
	         "usage: \"windham <action> <target>\"\n"
	         "For help, type 'windham Help' to view help for all possible actions\n\n"
	         
	         "This program comes with ABSOLUTELY NO WARRANTY; for details type 'Help --license'.\n"
	         "This is free software, and you are welcome to redistribute it under certain conditions;\n"), VERSION);
	exit(0);
}

void frontend_check_invalid_combo(int action_num) {
	if (options[NMOBJ_key] + options[NMOBJ_key_file] + options[NMOBJ_master_key] > 1) {
		print_error(_("argument --key, --key-file and --master-key are mutually exclusive."));
	}
	if (action_num == 4 && options[NMOBJ_key] + options[NMOBJ_key_file] + options[NMOBJ_master_key] + options[NMOBJ_target_slot] > 1) {
		print_error(_("argument --key, --key-file, --master-key and --target-slot are mutually exclusive under action: RevokeKey."));
	}
	
	if (action_num == 0 && options[NMOBJ_to] == 0 && options[NMOBJ_target_dry_run] == 0) {
		print_error(_("argument --to is required under action: Open"));
	}
	
	if (options[NMOBJ_target_obliterate] == 1 && options[NMOBJ_key] + options[NMOBJ_key_file] + options[NMOBJ_master_key] + options[NMOBJ_target_slot] + options[NMOBJ_target_mem] +
	                                             options[NMOBJ_target_time] != 0) {
		print_error(_("argument --obliterate can only be use alone."));
	}
	
	if (options[NMOBJ_target_obliterate] + options[NMOBJ_target_all] + options[NMOBJ_target_slot] > 1) {
		print_error(_("argument --all, --obliterate or --target-slot are mutually exclusive."));
	}
}


uint8_t hex_char_to_int(char ch) {
	if (ch == 0) {
		print_error(_("error when parsing master key: invalid length"));
	}
	if ('0' <= ch && ch <= '9') { return ch - '0'; }
	if ('a' <= ch && ch <= 'f') { return ch - 'a' + 10; }
	print_error(_("error when parsing master key: invalid character; only hexadecimal is accepted."));
	return -1;
}


void master_key_to_byte_array(const char * hex_string, uint8_t byte_array[HASHLEN]) {
	int str_index = 0, byte_index = 0;
	while (byte_index != HASHLEN) {
		while (hex_string[str_index] == ' ' || hex_string[str_index] == '-') {
			++str_index;
		}
		
		int high_nibble = hex_char_to_int(hex_string[str_index]);
		++str_index;
		while (hex_string[str_index] == ' ' || hex_string[str_index] == '-') {
			++str_index;
		}
		
		int low_nibble = hex_char_to_int(hex_string[str_index]);
		
		byte_array[byte_index] = (high_nibble << 4) + low_nibble;
		str_index++;
		++byte_index;
	}
	while (hex_string[str_index] == ' ' || hex_string[str_index] == '-') {
		++str_index;
	}
	if (hex_string[str_index] != 0) {
		printf(_("error when parsing master key: invalid length"));
		exit(1);
	}
}

void frontend_create_key(char * params[], Key * key, char * device, bool is_systemd) {
	if (options[NMOBJ_key] == 1) {
		key->key_or_keyfile_location = params[NMOBJ_key];
		key->key_type = EMOBJ_key_file_type_key;
	} else if (options[NMOBJ_key_file] == 1) {
		key->key_or_keyfile_location = params[NMOBJ_key_file];
		key->key_type = EMOBJ_key_file_type_file;
	} else {
		if (is_systemd) {
			key->key_or_keyfile_location = get_key_input_from_the_console_systemd(device);
		}
		key->key_or_keyfile_location = get_key_input_from_the_console(device, false);
		key->key_type = EMOBJ_key_file_type_input;
	}
}

#define ASK_KEY \
\
if (options[NMOBJ_master_key]) { \
master_key_to_byte_array(params[NMOBJ_master_key], master_key); \
} else { \
frontend_create_key(params, &key, device, options[NMOBJ_is_systemd]);\
}\


void frontend_check_validity_and_execute(int action_num, char * device, char * params[]) {
	uint8_t master_key[HASHLEN];
	int target_slot = -1;
	int unlock_slot = -1;
	size_t target_mem = 0;
	size_t max_unlock_mem = 0;
	double target_time = DEFAULT_TARGET_TIME;
	double max_unlock_time = DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR;
	size_t block_size = DEFAULT_BLOCK_SIZE;
	
	
	frontend_check_invalid_param(action_num);
	frontend_check_invalid_combo(action_num);
	if (memcmp(device, "--", 2) == 0) {
		print_error(_("arguments should locate after <device>. "));
	}
	
	char * end;
	if (options[NMOBJ_target_slot] == 1) {
		target_slot = (int) strtoimax(params[NMOBJ_target_slot], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an integer"), "--target-slot");
		}
		if (target_slot < 0 || target_slot >= KEY_SLOT_COUNT) {
			print_error(_("bad input for argument %s: slot out of range. Slot count starts at 0, to %i"), "--target-slot", KEY_SLOT_COUNT - 1);
		}
	}
	if (options[NMOBJ_unlock_slot] == 1) {
		unlock_slot = (int) strtoimax(params[NMOBJ_unlock_slot], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an integer"), "--unlock-slot");
		}
		if (unlock_slot < 0 || unlock_slot >= KEY_SLOT_COUNT) {
			print_error(_("bad input for argument %s: slot out of range. Slot count starts at 0, to %i"), "--unlock-slot", KEY_SLOT_COUNT - 1);
		}
	}
	if (options[NMOBJ_target_mem] == 1) {
		target_mem = strtoull(params[NMOBJ_target_mem], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--target-memory");
		}
	}
	if (options[NMOBJ_target_time] == 1) {
		target_time = strtod(params[NMOBJ_target_time], &end);
		if (*end != '\0' || target_time < 0) {
			print_error(_("bad input for argument %s: not an positive integer"), "--target-time");
		}
	}
	if (options[NMOBJ_max_unlock_mem] == 1) {
		max_unlock_mem = strtoull(params[NMOBJ_max_unlock_mem], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--max-unlock-memory");
		}
	}
	if (options[NMOBJ_max_unlock_time] == 1) {
		if (strcmp(params[NMOBJ_max_unlock_time], "-") == 0) {
			max_unlock_time = DBL_MAX;
		} else {
			max_unlock_time = strtod(params[NMOBJ_max_unlock_time], &end);
			if (*end != '\0' || target_time < 0) {
				print_error(_("bad input for argument %s: not an positive integer"), "--max-unlock-time");
			}
		}
	}
	if (options[NMOBJ_block_size] == 1) {
		block_size = strtoull(params[NMOBJ_block_size], &end, 10);
		if (*end != '\0' || (block_size != 512 && block_size != 1024 && block_size != 2048 && block_size != 4096)) {
			print_error(_("bad input for argument --block-size: not 512, 1024, 2048 or 4096"));
		}
	}
	
	if (!options[NMOBJ_is_noadmin]) {
		is_running_as_root();
	}
	if (options[NMOBJ_yes]) {
		is_skip_conformation = true;
	}
	
	init();
	Key key;
	key.key_or_keyfile_location = NULL;
	key.key_type = EMOBJ_key_file_type_none;
	
	// execute
	// "Open", "Close", "New", "AddKey", "RevokeKey", "Backup", "Restore", "Suspend", "Resume"
	switch (action_num) {
		case 0:
			check_file(device, !options[NMOBJ_target_readonly], options[NMOBJ_is_nofail]);
			check_is_device_mounted(device);
			if (!action_open_suspended(device, params[NMOBJ_to], options[NMOBJ_target_decoy], options[NMOBJ_target_dry_run], options[NMOBJ_target_readonly], options[NMOBJ_target_allow_discards],
												options[NMOBJ_target_no_read_workqueue], options[NMOBJ_target_no_write_workqueue])) {
				ASK_KEY
				action_open(device, params[NMOBJ_to], key, master_key, unlock_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy], options[NMOBJ_target_dry_run],
				            options[NMOBJ_target_readonly],options[NMOBJ_target_allow_discards], options[NMOBJ_target_no_read_workqueue], options[NMOBJ_target_no_write_workqueue]);
			}
			
			break;
		case 1:
			action_close(device);
			break;
		case 2:
			check_file(device, true, options[NMOBJ_is_nofail]);
			ASK_KEY
			action_create(device, params[NMOBJ_encrypt_type] ? params[NMOBJ_encrypt_type] : DEFAULT_DISK_ENC_MODE, key, target_slot, target_mem, target_time, options[NMOBJ_target_decoy], block_size);
			break;
		case 3:
			check_file(device, true, options[NMOBJ_is_nofail]);
			ASK_KEY
			
			action_addkey(device, key, master_key, unlock_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy], target_slot, target_mem, target_time);
			break;
		case 4:
			check_file(device, true, options[NMOBJ_is_nofail]);
			if (target_slot == -1 && options[NMOBJ_target_obliterate] == 0) {
				if (options[NMOBJ_target_all] == 0) {
					ASK_KEY
				}
			}
			action_revokekey(device, key, master_key, target_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy], options[NMOBJ_target_all], options[NMOBJ_target_obliterate]);
			break;
		case 5:
			check_file(device, false, options[NMOBJ_is_nofail]);
			if (!(options[NMOBJ_target_no_transform] || options[NMOBJ_target_restore])) {
				ASK_KEY
			}
			action_backup(device, params[NMOBJ_to], key, master_key, target_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy], options[NMOBJ_target_no_transform]);
			break;
		case 6:
			action_restore(device, params[NMOBJ_to], options[NMOBJ_target_decoy]);
			break;
		case 7:
			check_file(device, true, options[NMOBJ_is_nofail]);
			ASK_KEY
			action_suspend(device, key, master_key, target_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy]);
			break;
		case 8:
			check_file(device, true, options[NMOBJ_is_nofail]);
			ASK_KEY
			action_resume(device, key, master_key, target_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy]);
			break;
		default:
	}
	exit(EXIT_SUCCESS);
	
}


int main(int argc, char * argv[argc]) {
	char currentPath[PATH_MAX];
	char * absolutePath = realpath(argv[0], currentPath);
	
	if (absolutePath) {
		char * lastSlash = strrchr(absolutePath, '/');
		if (lastSlash) {
			*lastSlash = '\0';
		}
		
		char localePath[PATH_MAX];
		
		setlocale(LC_ALL, "");
		snprintf(localePath, sizeof(localePath), "%s/locale", absolutePath);
		bindtextdomain("windham", localePath);
		textdomain("windham");
	}
	
	char * params[NMOBJ_target_SIZE] = {NULL}; // the number of required arguments.
	
	if (argc == 1) {
		frontend_no_input();
	}
	
	int action_num = frontend_check_actions(argv[1]);
	
	if (argc == 2) {
		if (action_num == -1) {
			frontend_help(NULL);
		} else {
			print_error(_("<target> not provided. type 'windham Help' to view help"));
		}
	}
	
	if (argc >= 3) {
		if (action_num == -1) {
			frontend_help(argv[2]);
		}
		
		int opt;
		int long_index = 0;
		optind = 3;
		opterr = 0;
		
		while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
			if (opt == 0) {
				params[long_index] = optarg;
			} else {
				print_error(_("Unknown option or missing parameter for %s"), argv[optind - 1]);
			}
		}
		frontend_check_validity_and_execute(action_num, argv[2], params);
		exit(EXIT_SUCCESS);
	}
}
