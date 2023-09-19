#include "enclib.c"
#include "backend.c"
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <getopt.h>
#include <stdnoreturn.h>

#define THE_NAME_OF_THIS_SOFTWARE "windham"

enum {
	NMOBJ_map_to,
	NMOBJ_key,
	NMOBJ_key_file,
	NMOBJ_master_key,
	NMOBJ_target_slot,
	NMOBJ_max_unlock_mem,
	NMOBJ_max_unlock_time,
	NMOBJ_target_mem, //AddKey only
	NMOBJ_target_time, //AddKey only
	NMOBJ_encrypt_type,
	
	NMOBJ_target_all,
	NMOBJ_target_format,
	NMOBJ_target_obliterate,
	NMOBJ_target_dry_run,
	NMOBJ_target_decoy,
	NMOBJ_target_readonly,
	NMOBJ_target_noadmin,
	NMOBJ_target_yes,
	
	NMOBJ_target_SIZE,
};

const char * const actions[] = {"Open", "Close", "New", "AddKey", "RevokeKey", "Help"};
int options[NMOBJ_target_SIZE] = {0};

const struct option long_options[] = {
		{"map-to",            required_argument, &options[NMOBJ_map_to],          1},
		{"key",               required_argument, &options[NMOBJ_key],             1},
		{"key-file",          required_argument, &options[NMOBJ_key_file],        1},
		{"master-key",        required_argument, &options[NMOBJ_master_key],      1},
		{"target-slot",       required_argument, &options[NMOBJ_target_slot],     1},
		{"max-unlock-memory", required_argument, &options[NMOBJ_max_unlock_mem],  1},
		{"max-unlock-time",   required_argument, &options[NMOBJ_max_unlock_time], 1},
		{"target-memory",     required_argument, &options[NMOBJ_target_mem],      1},
		{"target-time",       required_argument, &options[NMOBJ_target_time],     1},
		{"encrypt-type",      required_argument, &options[NMOBJ_encrypt_type],    1},
		
		{"all",               no_argument,       &options[NMOBJ_target_all],      1},
		{"format",            no_argument,       &options[NMOBJ_target_format],   1},
		{"obliterate",            no_argument,       &options[NMOBJ_target_obliterate],   1},
		{"dry-run",           no_argument,       &options[NMOBJ_target_dry_run],  1},
		{"decoy", no_argument, &options[NMOBJ_target_decoy], 1},
		{"readonly",          no_argument,       &options[NMOBJ_target_readonly], 1},
		{"no-admin",          no_argument,       &options[NMOBJ_target_noadmin],  1},
		{"yes",               no_argument,       &options[NMOBJ_target_yes],      1},
		{0, 0,                                   0,                               0}
};

const int8_t check_allowed[] =
		// Open
		{NMOBJ_map_to, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_target_slot, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_target_readonly,
		 NMOBJ_target_dry_run, NMOBJ_target_decoy, NMOBJ_target_noadmin, NMOBJ_target_yes, -1,
				// Close
		 NMOBJ_target_noadmin, -1,
				// New
		 NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_target_slot, NMOBJ_target_mem, NMOBJ_target_time, NMOBJ_encrypt_type, NMOBJ_target_format,
		 NMOBJ_target_decoy, NMOBJ_target_noadmin, NMOBJ_target_yes, -1,
				// AddKey
		 NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_target_slot, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_target_mem, NMOBJ_target_time,
		 NMOBJ_target_decoy, NMOBJ_target_noadmin, NMOBJ_target_yes, -1,
				// RevokeKey
		 NMOBJ_key, NMOBJ_key_file, NMOBJ_target_slot, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_target_all, NMOBJ_target_obliterate,
		 NMOBJ_target_decoy, NMOBJ_target_noadmin, NMOBJ_target_yes, -1};


int frontend_check_actions(char * input) {
	for (int i = 0; (size_t)i < sizeof(actions) / sizeof(char *); i++) {
		if (strcmp(actions[i], input) == 0) {
			return i;
		}
	}
	if (memcmp(input, "--", 2) == 0){
		print_error("Arguments should locate after <action> and <target>.");
	}
	print_error("<action> not recognized. type '"THE_NAME_OF_THIS_SOFTWARE" Help' to view help");
}

noreturn void frontend_help(const char * the_3rd_argv) {
	if (!the_3rd_argv) {
		printf("usage: \"windham <action> <target>\"\n"
				"possible actions are: " " Open " " Close " " New " " AddKey " " RevokeKey\n\n"
				"Type \"windham Help <action>\" to view specific help text for each action.\n\n" );
		
		print("pre-compiled arguments. These arguments serve an informative purpose; changing them may render your\n"
				"device inaccessible.");
		print("number of keyslots: ", KEY_SLOT_COUNT);
		print("Length of the hash (bit): ", HASHLEN * CHAR_BIT);
		print("Argon2id memory size exponential count: ", KEY_SLOT_EXP_MAX);
		print("Argon2id base memory size (KiB): ", BASE_MEM_COST);
		print("Argon2id parallelism: ", PARALLELISM);
		print("Default encryption target time multiplier: ", DEFAULT_ENC_TARGET_TIME);
		print("Default decryption benchmark multiplier: ", MAX_UNLOCK_TIME_FACTOR);
		print("Default encryption type: ", DEFAULT_DISK_ENC_MODE);
		print("\n");
	} else if (strcmp("--license", the_3rd_argv) == 0) {
		printf("    Copyright (C) 2023-  W. Wang (level-128)\n"
				"\n"
				"    This program is free software: you can redistribute it and/or modify\n"
				"    it under the terms of the GNU General Public License as published by\n"
				"    the Free Software Foundation, either version 3 of the License, or\n"
				"    (at your option) any later version.\n"
				"\n"
				"    This program is distributed in the hope that it will be useful,\n"
				"    but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
				"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
				"    GNU General Public License for more details.\n"
				"\n"
				"    You should have received a copy of the GNU General Public License\n"
				"    along with this program.  If not, see <https://www.gnu.org/licenses/>.\n");
		
	} else if (strcmp(actions[0], the_3rd_argv) == 0) {
		printf("Open <target>: Unlock <target> and create a mapper. The key, by default, is read from the terminal.\n"
				"\n"
				"options:\n"
				"\t--map-to <location>: the target location of the mapper. The mapper will be named as <location>, locate under /dev/mapper/<location>\n"
				"\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
				"\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' and '--target-slot' are mutually exclusive\n"
				"\t--master-key <characters>: using master key to unlock."
				"\t--target-slot <int>: choose the target slot to perform the unlock operation. Other slots are ignored. \n"
				"\t--max-unlock-memory <int>: The total maximum available memory to use (KiB) available for decryption. \n"
				"\t--max-unlock-time <float>: the suggested total time (sec) to compute the key.\n"
				"\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"
				"\t--dry-run: run without operating on the block device.\n"
				"\t--readonly: Set the mapper device to read-only.\n"
				"\t--no-admin: forfeit checking root privileges, may produces undefined behaviour. ");
	} else if (strcmp(actions[1], the_3rd_argv) == 0) {
		printf("Close <target> close the encrypt block device.\n"
				"\n"
				"options:\n"
				"\t--no-admin: forfeit checking root privileges, may produces undefined behaviour. \n");
	} else if (strcmp(actions[2], the_3rd_argv) == 0) {
		printf("Create <target>: create a "THE_NAME_OF_THIS_SOFTWARE" header on a block device and add a new key. DO NOT COPY THE HEADER FROM OTHER ENCRYPTED DISKS, BECAUSE THEY "
				"COULD BE UNLOCKED USING THE SAME MASTER KEY. \n"
			  "\n"
			  "options:\n"
			  "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
			  "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' are mutually exclusive\n"
			  "\t--target-slot <int>: choose the target slot to add a new key; the first empty slot will be chosen as default.\n"
			  "\t--target-memory <int>: The total maximum memory (KiB) available for adding a key to use. \n"
			  "\t--target-time <float>: the suggested total time (sec) for adding a key. This is not a hard limit.\n"
			  "\t--decoy: Create a decoy FAT32 partition. The encrypted partition stores at the unallocated sector of the FAT32 filesystem.\n"
			  "\t--visible: adding partition identifier to the header. The program does not depend on the partition identifier; it will simply ignore it.\n"
			  "\t--no-admin: forfeit checking root privileges, may produces undefined behaviour. \n"
			  "\t--yes: do not ask for explicit conformation to potential destructive operations.\n");
	} else if (strcmp(actions[3], the_3rd_argv) == 0) {
		printf("AddKey <target>: Add a new key to the existing "THE_NAME_OF_THIS_SOFTWARE" header. The new key will be asked after a successful unlock from the given key.\n"
			  "\n"
			  "options:\n"
			  "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
			  "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' and '--target-slot' are mutually exclusive\n"
			  "\t--master-key <characters>: using master key to unlock."
			  "\t--target-slot <int>: choose the target slot to perform unlock operation. Other slots will be ignored. \n"
			  "\t--target-memory <int>: The total maximum memory (KiB) available for adding a key to use. \n"
			  "\t--target-time <float>: the suggested total time (sec) for adding a key. This is not a hard limit.\n"
			  "\t--max-unlock-memory <int>: The total maximum available memory to use (KiB) available for decryption. \n"
			  "\t--max-unlock-time <float>: the suggested total time (sec) to compute the key.\n"
			  "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"
			  "\t--no-admin: forfeit checking root privileges, may produces undefined behaviour. \n"
			  "\t--yes: do not ask for explicit conformation to potential destructive operations.\n");
	} else if (strcmp(actions[4], the_3rd_argv) == 0) {
		printf("RevokeKey <target>: remove a existing key from the header.\n"
				"\n"
				"options:\n"
				"\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
				"\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key', '--key-file' and '--target-slot' are mutually exclusive.\n"
				"\t--master-key <characters>: using master key to unlock."
				"\t--target-slot <int>: choose the target slot to perform the unlock operation. Other slots are ignored. \n"
				"\t--max-unlock-memory <int>: The total maximum available memory to use (KiB) available for decryption. \n"
				"\t--max-unlock-time <float>: the suggested total time (sec) to compute the key.\n"
				"\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"
				"\t--no-admin: forfeit checking for root privileges, may produces undefined behavior. \n"
				"\t--yes: do not ask for explicit conformation to potential destructive operations; in this case, it may render the device inaccessible if no master key backup have "
				"been created.\n");
	}
	exit(0);
}

noreturn void frontend_no_input() {
	printf("Windham  Copyright (C) 2023-  W. Wang (level-128)\n\n"
			 
			 "usage: \"windham <action> <target>\"\n"
			 "For help, type 'windham Help' to view help for all possible actions\n\n"
			 
			 "This program comes with ABSOLUTELY NO WARRANTY; for details type 'Help --license'.\n"
			"This is free software, and you are welcome to redistribute it under certain conditions;\n");
	exit(0);
}


void frontend_check_unvalid_param(int action_num) {
	int cnt = 0;
	for (int i = 0; (size_t)i < sizeof(actions) / sizeof(char *); i++) {
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
				print_error("argument:", (char *) long_options[i].name, "is not valid under action:", (char *) actions[action_num]);
			}
		}
	}
}




uint8_t hex_char_to_int(char ch) {
	if (ch == 0) {
		print_error("error length of the string.");
	}
	if ('0' <= ch && ch <= '9') { return ch - '0'; }
	if ('a' <= ch && ch <= 'f') { return ch - 'a' + 10; }
	print_error("invalid character in string.");
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
		printf("error length of the string.");
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
	} else {
		key->key_or_keyfile_location = get_key_input_from_the_console();
		key->key_type = EMOBJ_key_file_type_input;
	}
}

#define ASK_KEY \
if(options[NMOBJ_target_format] == 0 && options[NMOBJ_target_all] == 0) { \
if (options[NMOBJ_master_key]) { \
master_key_to_byte_array(params[NMOBJ_master_key], master_key); \
} else { \
frontend_create_key(params, &key);\
}\
}\
\


void frontend_check_validity_and_execute(int action_num, char * device, char * params[]) {
	uint8_t master_key[HASHLEN];
	int target_slot = -1;
	uint64_t target_mem = 0;
	uint64_t max_unlock_mem = 0;
	double target_time = DEFAULT_TARGET_TIME;
	double max_unlock_time = DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR;
	
	Key key;
	
	
	frontend_check_unvalid_param(action_num);
	if (options[NMOBJ_key] + options[NMOBJ_key_file] + options[NMOBJ_master_key] > 1) {
		print_error("argument --key, --key-file and --master-key are mutually exclusive.");
	}
	if (action_num == 4 && options[NMOBJ_key] + options[NMOBJ_key_file] + options[NMOBJ_master_key] + options[NMOBJ_target_slot] > 1) {
		print_error("argument --key, --key-file, --master-key and --target-slot are mutually exclusive under action: RevokeKey.");
	}
	
	if (action_num == 0 && options[NMOBJ_map_to] == 0 && options[NMOBJ_target_dry_run] == 0) {
		print_error("argument --map-to is required under action: Open");
	}
	
	if (options[NMOBJ_target_format] == 1 && options[NMOBJ_key] + options[NMOBJ_key_file] + options[NMOBJ_master_key] + options[NMOBJ_target_slot] + options[NMOBJ_target_mem] +
	options[NMOBJ_target_time] != 0) {
		print_error("argument --format can only be use alone.");
	}
	
	if (options[NMOBJ_target_obliterate] + options[NMOBJ_target_all] == 2){
		print_error("argument --all and --obliterate applies at the same time");
	}
	
	char * end;
	if (options[NMOBJ_target_slot] == 1) {
		target_slot = (int) strtoimax(params[NMOBJ_target_slot], &end, 10);
		if (*end != '\0') { print_error("bad input for argument --target-slot: not an integer"); }
		if (target_slot < 0 || target_slot >= KEY_SLOT_COUNT) { print_error("bad input for argument --target-slot: slot out of range"); }
	}
	if (options[NMOBJ_target_mem] == 1) {
		target_mem = strtoull(params[NMOBJ_target_mem], &end, 10);
		if (*end != '\0') { print_error("bad input for argument --target-memory: not an positive integer"); }
	}
	if (options[NMOBJ_target_time] == 1) {
		target_time = strtod(params[NMOBJ_target_time], &end);
		if (*end != '\0' || target_time < 0) { print_error("bad input for argument --target-time: not an positive number"); }
	}
	if (options[NMOBJ_max_unlock_mem] == 1) {
		max_unlock_mem = strtoull(params[NMOBJ_max_unlock_mem], &end, 10);
		if (*end != '\0') { print_error("bad input for argument --max-unlock-memory: not an positive integer"); }
	}
	if (options[NMOBJ_max_unlock_time] == 1) {
		max_unlock_time = strtod(params[NMOBJ_max_unlock_time], &end);
		if (*end != '\0' || target_time < 0) { print_error("bad input for argument --max-unlock-time: not an positive number"); }
	}
	
	if (!options[NMOBJ_target_noadmin]) {
		is_running_as_root();
	}
	
	init();
	
	switch (action_num) {
		case 0:
			check_is_device_mounted(device);
			
			ASK_KEY
			
			target_slot = action_open(device, params[NMOBJ_map_to], options[NMOBJ_master_key] ? NULL : &key, master_key, target_slot, max_unlock_mem, max_unlock_time,
											  options[NMOBJ_target_readonly], options[NMOBJ_target_dry_run], options[NMOBJ_target_decoy]);
			if (options[NMOBJ_target_dry_run]) {
				printf("dry run complete. Slot %i opened with master key:\n", target_slot);
				print_hex_array( HASHLEN, master_key);
			}
			break;
		case 1:
			action_close(device);
			break;
		case 2:
			check_is_device_mounted(device);
			if (options[NMOBJ_target_format]){
				ask_for_conformation("Formatting device: %s, All content will be lost. Continue?", device);
				action_create_format(device, options[NMOBJ_target_decoy]);
			} else {
				
				ASK_KEY
				
				ask_for_conformation("Creating encrypt partition on device: %s, All content will be lost. Continue?", device);
				action_create(device, params[NMOBJ_encrypt_type], key, target_mem, target_time, options[NMOBJ_target_decoy]);
			}
			break;
		case 3:
			
			ASK_KEY
			
			action_addkey(device, &key, master_key, target_slot, max_unlock_mem, max_unlock_time, target_mem, target_time, options[NMOBJ_target_decoy]);
			break;
		case 4:
			if (target_slot == -1) {
				ASK_KEY
			}
			action_revokekey(device, &key, master_key, target_slot, max_unlock_mem, max_unlock_time, params[NMOBJ_target_all], options[NMOBJ_target_obliterate], options[NMOBJ_target_decoy]);
			break;
		default:
		
	}
	exit(EXIT_SUCCESS);
	
}

int main(int argc, char * argv[]) {
	
	
	char * params[NMOBJ_target_SIZE] = {NULL}; // the number of required arguments.
	
	if (argc == 1) {
		frontend_no_input();
	}
	
	int action_num = frontend_check_actions(argv[1]);
	
	if (argc == 2) {
		if (action_num == 5) {
			frontend_help(NULL);
		} else {
			print_error("<target> not provided. type '"THE_NAME_OF_THIS_SOFTWARE" Help' to view help");
		}
	}
	
	if (argc >= 3) {
		if (action_num == 5) {
			frontend_help(argv[2]);
		} else {
			
			
			
			int opt;
			int long_index = 0;
			optind = 3;
			opterr = 0;
			
			while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) {
				if (opt == 0) {
					params[long_index] = optarg;
				} else {
					print_error("Unknown option or missing parameter for:", argv[optind - 1]);
				}
			}
			
			frontend_check_validity_and_execute(action_num, argv[2], params);
			exit(EXIT_SUCCESS);
		}
	}
}