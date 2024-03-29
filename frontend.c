#include "windham_const.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdnoreturn.h>
#include <float.h>

#include <libintl.h>
#include <locale.h>


#define DEFAULT_EXEC_DIR "/etc/windham"

#include "library_intrnlsrc/enclib.c"
#include "library_intrnlsrc/argon_bench.c"
#include "library_intrnlsrc/libloop.c"
#include "backend/bklibmain.c"

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
	NMOBJ_unlock_timeout,
	NMOBJ_encrypt_type,
	NMOBJ_block_size,
	NMOBJ_section_size,
	
	NMOBJ_target_all,
	NMOBJ_target_obliterate,
	NMOBJ_target_dry_run,
	NMOBJ_verbose,
	NMOBJ_target_no_transform,
	NMOBJ_is_no_detect_entropy,
	NMOBJ_target_restore,
	NMOBJ_target_decoy,
	NMOBJ_target_readonly,
	NMOBJ_target_allow_discards,
	NMOBJ_target_no_read_workqueue,
	NMOBJ_target_no_write_workqueue,
	NMOBJ_is_systemd,
	NMOBJ_is_dynamic_convert,
	NMOBJ_is_nokeyring,
	NMOBJ_is_nofail,
	NMOBJ_is_noadmin,
	NMOBJ_is_no_map_partition,
	NMOBJ_yes,
	NMOBJ_print_debug,
	
	NMOBJ_help,
	
	NMOBJ_target_SIZE,
};

const char * const actions[] = {"Help", "--help", "-h", "Open", "Close", "New", "AddKey", "RevokeKey", "Backup", "Restore", "Suspend", "Resume", "Bench"};
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
		{"timeout",            required_argument, &options[NMOBJ_unlock_timeout],            1},
		{"encrypt-type",       required_argument, &options[NMOBJ_encrypt_type],              1},
		{"block-size",         required_argument, &options[NMOBJ_block_size],                1},
		{"section-size",       required_argument, &options[NMOBJ_section_size],              1},
		
		{"all",                no_argument,       &options[NMOBJ_target_all],                1},
		{"obliterate",         no_argument,       &options[NMOBJ_target_obliterate],         1},
		{"dry-run",            no_argument,       &options[NMOBJ_target_dry_run],            1},
		{"verbose",            no_argument,       &options[NMOBJ_verbose],                   1},
		{"no-transform",       no_argument,       &options[NMOBJ_target_no_transform],       1},
		{"no-detect-entropy",  no_argument,       &options[NMOBJ_is_no_detect_entropy],      1},
		{"restore",            no_argument,       &options[NMOBJ_target_restore],            1},
		{"decoy",              no_argument,       &options[NMOBJ_target_decoy],              1},
		{"readonly",           no_argument,       &options[NMOBJ_target_readonly],           1},
		{"allow-discards",     no_argument,       &options[NMOBJ_target_allow_discards],     1},
		{"no-read-workqueue",  no_argument,       &options[NMOBJ_target_no_read_workqueue],  1},
		{"no-write-workqueue", no_argument,       &options[NMOBJ_target_no_write_workqueue], 1},
		{"systemd-dialog",     no_argument,       &options[NMOBJ_is_systemd],                1},
		{"dynamic-convert",    no_argument,       &options[NMOBJ_is_dynamic_convert],        1},
		{"nokeyring",          no_argument,       &options[NMOBJ_is_nokeyring],              1},
		{"nofail",             no_argument,       &options[NMOBJ_is_nofail],                 1},
		{"noadmin",            no_argument,       &options[NMOBJ_is_noadmin],                1},
		{"no-map-partition",   no_argument,       &options[NMOBJ_is_no_map_partition],       1},
		{"yes",                no_argument,       &options[NMOBJ_yes],                       1},
		{"help",               no_argument,       &options[NMOBJ_help],                      1},
		{"pdebug",             no_argument,       &options[NMOBJ_print_debug],               1},
		{0, 0,                                    0,                                         0}
};

#define CHECK_ALLOWED_OPEN NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_unlock_slot, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_target_decoy, NMOBJ_verbose, \
NMOBJ_is_systemd, NMOBJ_is_nofail

#define CHECK_COMMON NMOBJ_is_noadmin, NMOBJ_yes, NMOBJ_print_debug, NMOBJ_help

const int8_t check_allowed[] =
		// Open
		{CHECK_ALLOWED_OPEN, NMOBJ_to, NMOBJ_unlock_timeout, NMOBJ_target_readonly, NMOBJ_target_dry_run, NMOBJ_target_allow_discards, NMOBJ_target_no_read_workqueue, NMOBJ_target_no_write_workqueue,
		 NMOBJ_is_nokeyring, NMOBJ_is_no_map_partition, CHECK_COMMON, -1,
				// Close
       CHECK_COMMON, -1,
				// New
       NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_target_slot, NMOBJ_target_mem, NMOBJ_target_time, NMOBJ_encrypt_type, NMOBJ_target_decoy, NMOBJ_block_size, NMOBJ_is_systemd,
       NMOBJ_is_dynamic_convert, NMOBJ_section_size, NMOBJ_is_no_detect_entropy, CHECK_COMMON, -1,
				// AddKey
       CHECK_ALLOWED_OPEN, NMOBJ_max_unlock_time, NMOBJ_target_mem, NMOBJ_target_time, NMOBJ_is_no_detect_entropy, CHECK_COMMON, -1,
				// RevokeKey
       CHECK_ALLOWED_OPEN, NMOBJ_target_slot, NMOBJ_target_all, NMOBJ_target_obliterate, CHECK_COMMON, -1,
				// Backup
       CHECK_ALLOWED_OPEN, NMOBJ_to, NMOBJ_target_no_transform, CHECK_COMMON, -1,
				// Restore
       NMOBJ_to, CHECK_COMMON, -1,
				// Suspend
       CHECK_ALLOWED_OPEN, CHECK_COMMON, -1,
				// Resume
       CHECK_ALLOWED_OPEN, CHECK_COMMON, -1,
				// Bench
       -1};


int frontend_check_actions(char * input) {
	for (int i = 0; (size_t) i < sizeof(actions) / sizeof(char *); i++) {
		if (strcmp(actions[i], input) == 0) {
			return i >= 3 ? i - 3 : -1; // help will return -1
		}
	}
	if (memcmp(input, "--", 2) == 0) {
		print_error(_("Arguments should locate after <action> and <target>."));
	}
	print_error(_("<action> not recognized. type 'windham Help' to view help"));
	exit(1);
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
				print_error(_("argument: %s is not valid under action: %s"), (char *) long_options[i].name, (char *) actions[action_num + 3]);
			}
		}
	}
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
		print_error(_("argument --obliterate can only be used alone."));
	}
	
	if (options[NMOBJ_target_obliterate] + options[NMOBJ_target_all] + options[NMOBJ_target_slot] > 1) {
		print_error(_("argument --all, --obliterate or --target-slot are mutually exclusive."));
	}
	
	if (!options[NMOBJ_is_dynamic_convert] && options[NMOBJ_section_size]) {
		print_error(_("argument --section-size can only be used when enabling dynamic conversion"));
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

void frontend_create_key(char * params[], Key * key) {
	if (options[NMOBJ_key] == 1) {
		key->key_or_keyfile_location = params[NMOBJ_key];
		key->key_type = EMOBJ_key_file_type_key;
	} else if (options[NMOBJ_key_file] == 1) {
		key->key_or_keyfile_location = params[NMOBJ_key_file];
		key->key_type = EMOBJ_key_file_type_file;
	} else if (options[NMOBJ_is_systemd] == 1) {
		key->key_or_keyfile_location = NULL;
		key->key_type = EMOBJ_key_file_type_input_systemd;
	} else if (options[NMOBJ_master_key] == 1) {
		key->key_or_keyfile_location = NULL;
		key->key_type = EMOBJ_key_file_type_masterkey;
	} else {
		key->key_or_keyfile_location = NULL;
		key->key_type = EMOBJ_key_file_type_input;
	}
}

void init_key_obj_and_master_key(Key * key, uint8_t master_key[HASHLEN], char * params[]) {
	if (options[NMOBJ_master_key]) {
		master_key_to_byte_array(params[NMOBJ_master_key], master_key);
	} else {
		memset(master_key, 0, HASHLEN);
	}
	frontend_create_key(params, key);
}


noreturn void frontend_check_validity_and_execute(int action_num, const char * device, char * params[]) {
	uint8_t master_key[HASHLEN];
	int target_slot = -1;
	int unlock_slot = -1;
	size_t target_mem = 0;
	size_t max_unlock_mem = 0;
	double target_time = DEFAULT_TARGET_TIME;
	double max_unlock_time = DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR;
	unsigned timeout = 0;
	size_t block_size = DEFAULT_BLOCK_SIZE;
	size_t section_size = DEFAULT_SECTION_SIZE;
	
	print_verbose = false;
	print_enable = false;
	
	
	frontend_check_invalid_param(action_num);
	frontend_check_invalid_combo(action_num);
	
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
	if (options[NMOBJ_unlock_timeout] == 1) {
		timeout = strtoul(params[NMOBJ_unlock_timeout], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--timeout");
		}
	}
	if (options[NMOBJ_block_size] == 1) {
		block_size = strtoull(params[NMOBJ_block_size], &end, 10);
		if (*end != '\0' || (block_size != 512 && block_size != 1024 && block_size != 2048 && block_size != 4096)) {
			print_error(_("bad input for argument --block-size: not 512, 1024, 2048 or 4096"));
		}
	}
	if (options[NMOBJ_section_size] == 1) {
		section_size = strtoull(params[NMOBJ_section_size], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--section-size");
		} else if (section_size < block_size) {
			print_error(_("section size (%lu) is smaller than the block size (%lu)"), section_size, block_size);
		} else if (__builtin_popcount(section_size) != 1) {
			print_warning(_("section size is not 2^n."));
		}
	}
	
	if (!options[NMOBJ_is_noadmin]) {
		is_running_as_root();
	}
	is_skip_conformation = options[NMOBJ_yes];
	print_verbose = options[NMOBJ_verbose];
	
	init();

	Key key;
	init_key_obj_and_master_key(&key, master_key, params);
	
	// execute
	// "Open", "Close", "New", "AddKey", "RevokeKey", "Backup", "Restore", "Suspend", "Resume"
	switch (action_num) {
		case 0:
			init_device(device, true, options[NMOBJ_is_nofail]);
			action_open(STR_device->name, params[NMOBJ_to], timeout, key, master_key, unlock_slot, max_unlock_mem, max_unlock_time,
			            BOOL_DEL_START,
			            options[NMOBJ_target_dry_run],
							options[NMOBJ_target_decoy],
			            options[NMOBJ_target_readonly],
							options[NMOBJ_target_allow_discards],
			            options[NMOBJ_target_no_read_workqueue],
							options[NMOBJ_target_no_write_workqueue],
			            options[NMOBJ_is_no_map_partition],
			            options[NMOBJ_is_nokeyring],
			            BOOL_DEL_END);
			
			break;
		case 1:
			// do not init device, since the device is mapper's name.
			action_close(device);
			// loop frees inside it
			break;
		case 2:
			init_device(device, true, options[NMOBJ_is_nofail]);
			action_create(STR_device->name, params[NMOBJ_encrypt_type], key, target_slot, target_mem, target_time, block_size, section_size,
							  options[NMOBJ_target_decoy], options[NMOBJ_is_dynamic_convert], options[NMOBJ_is_no_detect_entropy]);
			break;
		case 3:
			init_device(device, false, options[NMOBJ_is_nofail]);
			
			action_addkey(STR_device->name, key, master_key, unlock_slot, max_unlock_mem, max_unlock_time, target_slot, target_mem, target_time, options[NMOBJ_target_decoy], options[NMOBJ_is_no_detect_entropy]);
			break;
		case 4:
			init_device(device, false, options[NMOBJ_is_nofail]);
			
			action_revokekey(STR_device->name, key, master_key, target_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_all], options[NMOBJ_target_obliterate], options[NMOBJ_target_decoy]);
			break;
		case 5:
			init_device(device, false, options[NMOBJ_is_nofail]);
			
			action_backup(STR_device->name, params[NMOBJ_to], key, master_key, target_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_no_transform], options[NMOBJ_target_decoy]);
			break;
		case 6:
			init_device(device, false, options[NMOBJ_is_nofail]);

			action_restore(STR_device->name, params[NMOBJ_to], options[NMOBJ_target_decoy]);
			break;
		case 7:
			init_device(device, false, options[NMOBJ_is_nofail]);
			
			action_suspend(STR_device->name, key, master_key, unlock_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy]);
			break;
		case 8:
			init_device(device, false, options[NMOBJ_is_nofail]);
			
			action_resume(STR_device->name, key, master_key, unlock_slot, max_unlock_mem, max_unlock_time, options[NMOBJ_target_decoy]);
			break;
		default:
			break;
	}
	longjmp(windham_exit, NMOBJ_windham_exit_normal);
	
}


int main(int argc, char * argv[argc]) {
	exit_init();
	
	char currentPath[PATH_MAX];
	char * absolutePath = realpath(argv[0], currentPath);
	char * params[NMOBJ_target_SIZE] = {NULL}; // the number of required arguments.
	
	
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
	
	if (argc == 1) {
		frontend_no_input();
	}
	
	int action_num = frontend_check_actions(argv[1]);
	if (action_num == -1) {
		frontend_help(argc > 2 ? argv[2] : NULL);
	}
	
	if (argc == 2) {
		if (action_num == 9) { // benchmark
			benchmark();
		} else { // run benchmark
			print_error(_("<target> not provided. type 'windham Help' to view help"));
		}
	}
	
	if (argc >= 3) {
		if (memcmp(argv[2], "-", 1) == 0) {
			if (strcmp(argv[2], "--help") == 0 || strcmp(argv[2], "-h") == 0) {
				frontend_help(argv[1]);
			}
			print_error(_("arguments should locate after <device>. "));
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
		if (options[NMOBJ_help]) {
			frontend_help(argv[1]);
		}
		frontend_check_validity_and_execute(action_num, argv[2], params);
		exit(EXIT_SUCCESS);
	}
}


