#include "enclib.c"
#include "backend.c"
#include "mapper.c"
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
	NMOBJ_target_slot,
	NMOBJ_max_unlock_mem,
	NMOBJ_max_unlock_time,
	NMOBJ_target_mem,
	NMOBJ_target_time,
	
	NMOBJ_target_dry_run,
	NMOBJ_target_readonly,
	NMOBJ_target_noadmin,
	NMOBJ_target_visible,
	NMOBJ_target_yes,
	NMOBJ_target_license,
	
	NMOBJ_target_SIZE,
};

const char * const actions[] = {"Open", "Close", "Create", "AddKey", "RemoveKey", "Backup", "Destroy", "Help"};
int options[NMOBJ_target_SIZE] = {0};

struct option long_options[] = {
		{"map-to",            required_argument, &options[NMOBJ_map_to],          1},
		{"key",               required_argument, &options[NMOBJ_key],             1},
		{"key-file",          required_argument, &options[NMOBJ_key_file],        1},
		{"target-slot",       required_argument, &options[NMOBJ_target_slot],     1},
		{"max-unlock-memory", required_argument, &options[NMOBJ_max_unlock_mem],  1},
		{"max-unlock-time",   required_argument, &options[NMOBJ_max_unlock_time], 1},
		{"target-memory",     required_argument, &options[NMOBJ_target_mem],      1},
		{"target-time",       required_argument, &options[NMOBJ_target_time],     1},
		
		{"dry-run",           no_argument,       &options[NMOBJ_target_dry_run],  1},
		{"readonly",          no_argument,       &options[NMOBJ_target_readonly], 1},
		{"no-admin",          no_argument,       &options[NMOBJ_target_noadmin],  1},
		{"visible",           no_argument,       &options[NMOBJ_target_visible],  1},
		{"yes",               no_argument,       &options[NMOBJ_target_yes],      1},
		{"license",           no_argument,       &options[NMOBJ_target_license],  1},
		{0, 0,                                   0,                               0}
};

void frontend_check_actions(char * input) {
	for (int i = 0; i < sizeof(actions) / sizeof(char *); i++) {
		if (strcmp(actions[i], input) == 0) {
			return;
		}
	}
	print_error("<target> not recognized. type '"THE_NAME_OF_THIS_SOFTWARE" Help' to view help");
}

noreturn void frontend_help(const char * the_3rd_argv) {
	if (!the_3rd_argv) {
		print("usage: '" THE_NAME_OF_THIS_SOFTWARE " <action> <target>'\n");
		print("possible actions are: ", "Open", "Close", "Create", "AddKey", "RemoveKey", "Backup", "Destroy\n"
																																  "\n"
				THE_NAME_OF_THIS_SOFTWARE" Open <target>: open a target and create a mapper. The key is read from the terminal by default\n"
				THE_NAME_OF_THIS_SOFTWARE" Close <target>: close the target. The target should be a mapper object.\n"
				THE_NAME_OF_THIS_SOFTWARE" Create <target>: create a new encrypted object\n"
				THE_NAME_OF_THIS_SOFTWARE" AddKey <target>: add a key to the object.\n"
				THE_NAME_OF_THIS_SOFTWARE" RemoveKey <target>: remove a key to the object.\n"
				THE_NAME_OF_THIS_SOFTWARE" Backup <target>: backup the master key of the object.\n"
				THE_NAME_OF_THIS_SOFTWARE" Destroy <target>: destroy the object and make it inaccessible under any form.\n\n");
		
		print("pre-compiled arguments. These arguments serve an informative purpose; changing them may render your\n"
				"partitions inaccessible by other devices. ");
		print("number of keyslots: ", KEY_SLOT_COUNT);
		print("Length of the hash (bit): ", HASHLEN * CHAR_BIT);
		print("Argon2id memory size exponential count: ", KEY_SLOT_COUNT);
		print("Argon2id base memory size: ", BASE_MEM_COST);
		print("Argon2id parallelism: ", PARALLELISM);
		print("Default encryption target time: ", DEFAULT_ENC_TARGET_TIME);
		print("\n");
	} else if (strcmp("--license", the_3rd_argv) == 0) {
		print("    Copyright (C) 2023-  W. Wang (level-128)\n"
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
				"    along with this program.  If not, see <https://www.gnu.org/licenses/>.");
		
	} else if (strcmp(actions[0], the_3rd_argv) == 0) {
		print("Open <target>: open the target and create a mapper. The key, by default, is read from the terminal.\n"
				"\n"
				"options:\n"
				"\t--map-to <location>: the target location of the mapper\n"
				"\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
				"\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' are mutually exclusive.\n"
				"\t--target-slot <int>: choose the target slot to perform unlock operation. Other slots will be ignored. \n"
				"\t--max-memory <int>: The total maximum available memory for Argon2id hashing function to use (KiB). \n"
				"\t--target-time <float>: the suggested total time (sec) for computing using hash functions. This is not a hard limit. The default value is 5 sec.\n"
				"\t--dry-run: run without operating on the block device.\n"
				"\t--readonly: make the mapper device read only\n"
				"\t--no-admin: forfeit checking for root privileges, may produces undefined behavior. ");
	} else if (strcmp(actions[1], the_3rd_argv) == 0) {
		print("Close <target> close the encrypt block device.\n"
				"\n"
				"options:\n"
				"\t--no-admin: forfeit checking for root privileges, may produces undefined behavior. ");
	} else if (strcmp(actions[2], the_3rd_argv) == 0) {
		print("Create <target>: create a "THE_NAME_OF_THIS_SOFTWARE" header on a block device and add a new key. DO NOT COPY THE HEADER FROM OTHER ENCRYPTED DEVICES, BECAUSE THEY CONTAINS THE SAME MASTER KEY. \n"
																					  "\n"
																					  "options:\n"
																					  "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
																					  "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' are mutually exclusive.\n"
																					  "\t--target-slot <int>: choose the target slot to add new key; the first empty slot will be chosen as default.\n"
																					  "\t--max-memory <int>: The total maximum available memory for Argon2id hashing function to use (KiB). \n"
																					  "\t--target-time <float>: the suggested total time (sec) for computing using hash functions. This is not a hard limit.\n"
																					  "\t--no-admin: forfeit checking for root privileges, may produces undefined behavior. \n"
																					  "\t--visible: adding partition identifier to the header. The program does not depend on the partition identifier; it will simply ignore it.\n"
																					  "\t--yes: do not ask for explicit conformation to potential destructive operations.");
	} else if (strcmp(actions[3], the_3rd_argv) == 0) {
		print("AddKey <target>: Add a new key to the existing "THE_NAME_OF_THIS_SOFTWARE" header. The new key will be asked after a successful unlock from the given key.\n"
																												  "\n"
																												  "options:\n"
																												  "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
																												  "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' are mutually exclusive.\n"
																												  "\t--target-slot <int>: choose the target slot to perform unlock operation. Other slots will be ignored. \n"
																												  "\t--max-memory <int>: The total maximum available memory for Argon2id hashing function to use (KiB). \n"
																												  "\t--target-time <float>: the suggested total time (sec) for computing using hash functions. This is not a hard limit. The default value is 5 sec.\n"
																												  "\t--no-admin: forfeit checking for root privileges, may produces undefined behavior. \n"
																												  "\t--yes: do not ask for explicit conformation to potential destructive operations.");
	} else if (strcmp(actions[4], the_3rd_argv) == 0) {
		print("RemoveKey <target>: remove a existing key from the header.\n"
				"\n"
				"options:\n"
				"\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
				"\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key', '--key-file' and '--target-slot' are mutually exclusive.\n"
				"\t--target-slot <int>: choose the target slot to erase, no unlock needed. Option '--key', '--key-file' and '--target-slot' are mutually exclusive. \n"
				"\t--max-memory <int>: The total maximum available memory for Argon2id hashing function to use (KiB). Mutually exclusive with '--target-slot'.\n"
				"\t--target-time <float>: the suggested total time (sec) for computing using hash functions. This is not a hard limit. Mutually exclusive with '--target-slot'.\n"
				"\t--no-admin: forfeit checking for root privileges, may produces undefined behavior. \n"
				"\t--yes: do not ask for explicit conformation to potential destructive operations; in this case, it may render the device inaccessible if no master key backup has been created.");
	} else if (strcmp(actions[5], the_3rd_argv) == 0) {
		print("");
	} else if (strcmp(actions[6], the_3rd_argv) == 0) {
		print("");
	}
	exit(0);
}


int main(int argc, char * argv[]) {

	
	if (argc == 1) {
		print(THE_NAME_OF_THIS_SOFTWARE"  Copyright (C) 2023-  Weizheng Wang (level-128)\n");
		
		print("usage: '" THE_NAME_OF_THIS_SOFTWARE " <action> <target>'");
		print("For help, type '"THE_NAME_OF_THIS_SOFTWARE" Help' to view help for all possible actions, or '"THE_NAME_OF_THIS_SOFTWARE" Help <action>'\n"
																																												"to view help info for individual action.\n");
		
		print("possible actions are: ", "Open", "Close", "Create", "AddKey", "RemoveKey", "Backup", "Restore", "Destroy\n");
		print("This program comes with ABSOLUTELY NO WARRANTY; for details type 'Help --license'.\n"
				"This is free software, and you are welcome to redistribute it under certain conditions;\n");
		exit(0);
	}
	
	frontend_check_actions(argv[1]);
	
	if (argc == 2) {
		if (strcmp(argv[1], "Help") == 0) {
			frontend_help(NULL);
		} else {
			print_error("<target> not provided. type '"THE_NAME_OF_THIS_SOFTWARE" Help' to view help");
		}
		exit(0);
	}
	
	char * target;
	target = argv[2];
	
	if (argc == 3) {
		if (strcmp(argv[1], "Help") == 0) {
			frontend_help(target);
		}
	}
}