//
// Created by level-128 on 1/19/24.
//

void frontend_print_unlock_args() {
	printf(_(
			       "\nUnlock options:\n"
			       "\t--key <characters>: key input as argument, instead of asking in the terminal.\n"
			       "\t--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' and '--target-slot' are mutually exclusive\n"
			       "\t--master-key <characters>: using master key to unlock.\n"
			       "\t--unlock-slot <int>: choose the slot to unlock; Other slots are ignored.\n"
			       "\t--max-unlock-memory <int>: total maximum available memory (KiB) available for decryption. \n"
			       "\t--max-unlock-time <float>: the suggested max time (sec) for unlock.\n"
			       "\t--verbose: print unlock progress per keyslot.\n"
			       "\t--systemd-dialog: use systemd password input dialog; useful when integrating with systemd.\n"));
};

void frontend_print_common_args() {
	printf(_(
			       "\nCommon options:\n"
			       "\t--no-admin: forfeit checking root privileges, may produces undefined behavior. \n"
			       "\t--yes: do not ask for explicit conformation to potential destructive operations.\n"
			       "\t--nofail: exit normally without error message when the device does not exist.\n"
			       "\t--help: print this message.\n"));
};

noreturn void frontend_help(const char * the_3rd_argv) {
	if (!the_3rd_argv) {
		printf(_("usage: \"windham <action> <target>\"\n"
		         "possible actions are:  'Open'  'Close'  'New'  'AddKey'  'RevokeKey' 'Backup' 'Restore' 'Suspend' and 'Resume'\n\n"
		         "Type \"windham Help <action>\" to view specific help text for each action.\n\n"
		         "pre-compiled arguments. These arguments serve an informative purpose; changing them may render your "
		         "device inaccessible.\n"));
		printf(_("number of keyslots: %i\n"), KEY_SLOT_COUNT);
		printf(_("Length of the hash (bits): %i\n"), HASHLEN * CHAR_BIT);
		printf(_("Argon2id memory size exponential count: %i\n"), KEY_SLOT_EXP_MAX);
		printf(_("Argon2id base memory size (KiB): %i\n"), BASE_MEM_COST);
		printf(_("Argon2id parallelism: %i\n"), PARALLELISM);
		printf(_("Wipe memory for Argon2B3: %b\n"), (bool) ARGON2_FLAG_CLEAR_MEMORY);
		printf(_("Default encryption target time: %i\n"), DEFAULT_ENC_TARGET_TIME);
		printf(_("Default decryption target time (per slot): %i\n"), MAX_UNLOCK_TIME_FACTOR);
		printf(_("Default encryption type: %s\n"), DEFAULT_DISK_ENC_MODE);
		printf(_("Default block size: %d\n"), DEFAULT_BLOCK_SIZE);
		printf(_("Default section size: %d\n"), DEFAULT_SECTION_SIZE);
		printf(_("\nSystem and compiler information:\n"));
#ifdef __GNUC__
		printf(_("Compiler: GCC %d.%d.%d\n"), __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elifdef __clang__
		printf(_("Compiler: Clang %d.%d.%d\n"), __clang_major__, __clang_minor__, __clang_patchlevel__);
#else
		printf(_("Unknown compiler\n"));
#endif
#if defined(CMAKE_VERSION)
		printf(_("System architecture: %s\n"), TARGET_ARCH);
		printf(_("Build host Architecture: %s"), HOST_ARCH);
		printf(_("Compile time (GMT): %s\n"), CURRENT_TIME);
		printf(_("CMake version: %s\n"), CMAKE_VERSION);
		printf(_("Target kernel version for this build: %s\n"), TARGET_KERNEL_VERSION);
#ifdef COMPILE_PARAMS
		printf(_("Compile Params: %s\n"), COMPILE_PARAMS);
#else
		printf(_("No Compile Params were givin, possibly debug build"));
#endif
#else // #if defined(CMAKE_VERSION)
		printf(_("Windham is not built by CMake, hence the system information is not avaliable."));
#endif // #if defined(CMAKE_VERSION)
	
	} else if (strcmp("--license", the_3rd_argv) == 0) {
		printf(_("    Copyright (C) 2023-2024  W. Wang (level-128)\n"
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
		
	} else if (strcmp("Open", the_3rd_argv) == 0) {
		printf(_("Open <target>: Unlock <target> and create a mapper (decrypted crypt device) under /dev/mapper/<location>. The key, by default, is read from the terminal.\n"
		         "\n"
		         "options:\n"
		         "\t--to <location>: REQUIRED; the target location of the mapper. The mapper will be named as <location>, locate under /dev/mapper/<location>\n"
		         "\t--timeout <int>: set unlock timeout (sec, default = 0) for password re-prompt when open. Keys are stored in the Linux Kernel Key Retention service (keyring service).\n"
		         "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, detect automatically.\n"
		         "\t--dry-run: run without operating on the block device then print the master key and device parameters.\n"
		         "\t--nokeyring: do not attempt to use keys in the Linux Kernel Key Retention service (keyring service).\n"
		         "\t--readonly: Create read only mapper device.\n"
		         "\t--allow-discards: Allow TRIM commands being sent to the crypt device.\n"
		         "\t--no-read-workqueue: Process read requests synchronously instead of using a internal workqueue.\n"
		         "\t--no-write-workqueue: Process write requests synchronously instead of using a internal workqueue.\n"
		         "\t--no-map-partition: do not map the partition table that reside inside the crypt device after unlock.\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp("Close", the_3rd_argv) == 0) {
		printf(_("Close <target> close the encrypt block device.\n"));
		frontend_print_common_args();
		
	} else if (strcmp("New", the_3rd_argv) == 0) {
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
					"\t--dynamic-convert: Dynamically convert an existing partition to Windham encrypted partition without reformatting.\n"
		         "\t--block-size <int>: designate the encryption sector size. Size must be 512, 1024, 2048 or 4096.\n"
					"\t--section-size <int>: designate the section size for dynamic partition conversion. A larger section size may increase the conversion speed, but will resulting more waste space "
					"resides before the first encrypt sector.\n"
		         "\t--decoy: Create a decoy FAT32 partition. The encrypted partition stores at the unallocated sector of the FAT32 filesystem.\n"));
		frontend_print_common_args();
		printf(_("A list of supported encryption mode on your system is located at file \"/proc/crypto\". If the designated encryption scheme contains an unsupported, "
		         "but valid, mode, a warning will be displayed, and the partition cannot be opened using your system.\n"));
		
	} else if (strcmp("AddKey", the_3rd_argv) == 0) {
		printf(_("AddKey <target>: Add a new key to the existing windham header. The new key will be asked after a successful unlock from the given key.\n"
		         "\n"
		         "options:\n"
		         "\t--target-memory <int>: The total maximum memory (KiB) available to use. \n"
		         "\t--target-time <float>: the suggested total time (sec) for adding a key. This is not a hard limit.\n"
		         "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp("RevokeKey", the_3rd_argv) == 0) {
		printf(_("RevokeKey <target>: remove a existing key from the header.\n"
		         "\n"
		         "options:\n"
		         "\t--target-slot <int>: revoke the key inside the target slot. No password required.\n"
		         "\t--all: revoke all slots; the device is inaccessible unless using master key to unlock.\n"
		         "\t--decoy: Opening the device assuming that the decoy partition exists; otherwise, auto-detect.\n"
		         "\t--obliterate: Wipe the header and destroy all data."));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp("Backup", the_3rd_argv) == 0) {
		printf(_("Backup <target>: Backup the header into a separate file.\n"
		         "\n"
		         "options:\n"
		         "\t--to <location>: REQUIRED; the location of the file.\n"
		         "\t--no-transform: backup the header as is. No key required. \n"
		         "\t--restore: restore the header from a backup file.\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp("Restore", the_3rd_argv) == 0) {
		printf(_("Restore <target>: Restore the header from a file to the device.\n"
		         "\n"
		         "options:\n"
		         "\t--to <location>: REQUIRED; the location of the file.\n"));
		
	} else if (strcmp("Suspend", the_3rd_argv) == 0) {
		printf(_("Suspend <target>: Make device identifiable and accessible without password. When Suspending, only 'Close' and 'RevokeKey' (With param '--all', '--obliterate' and "
		         "'--target-slot') could be used.\n"
		         "\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp("Resume", the_3rd_argv) == 0) {
		printf(_("Resume <target>: unsuspend the device.\n"
		         "\n"));
		frontend_print_unlock_args();
		frontend_print_common_args();
		
	} else if (strcmp("Bench", the_3rd_argv) == 0) {
		printf(_("Bench: Performing Argon2 benchmark\n"
		         "\n"));
	} else {
		print_error("<action> not recognized. type 'windham Help' to view help");
	}
	exit(0);
}