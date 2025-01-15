#pragma once

#include <limits.h>

#include "../library_intrnlsrc/srclib.c"




void frontend_print_unlock_args() {
  printf(_("\nUnlock options:\n"
	   "\t--key <characters>: password input as argument instead of asking in the terminal interactively.\n"
	   "\t--key-file <location>: password input as key file. The key file will be read as key (exclude EOF character). Option '--key', "
	   "'--key-file' and '--keystdin' are mutually exclusive.\n"
	   "\t--keystdin: read key from standard input. the key format must be 32-byte bit stream encoded using hexadecimal format. "
	   "spaces are ignored. Useful when intergrating with Clevis\n"
	   "\t--master-key <characters>: use master key to unlock.\n"
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	   "\t--decoy: OPTION UNAVAILABLE, big endian devices currently does not support decoy partition."
#else
	   "\t--decoy: Open a decoy device.\n"
#endif
	   "\t--max-unlock-memory <int>: total maximum available memory (KiB) available for decryption. \n"
	   "\t--max-unlock-time <float>: the suggested max time (sec) for unlock, \"-\" for unlimited.\n"
	   "\t--max-unlock-level <int>: the target derivation level for decryption.\n"
#ifdef CONFIG_USE_SWAP
	   "\t--allow-swap: Use swap space to derivate if needed. However swap deduces security.\n"
#else
	   "\t--allow-swap: OPTION UNAVAILABLE, not enabled during build.\n"
#endif
	   "\t--systemd-dialog: use systemd password dialog.\n"));
};


void frontend_print_common_args() {
   printf(_("\nCommon options:\n"
            "\t--no-admin: forfeit checking root privileges, may produces undefined behavior. \n"
            "\t--yes: do not ask for explicit conformation to potential destructive operations.\n"
            "\t--nofail: exit normally without error message when the device does not exist.\n"
            "\t--help: print this message.\n"));
};

void frontend_print_newpw_args() {
  printf(_("\nNew passphrase options:\n"
	   "\t--target-memory <int>: total maximum memory (KiB) available to use for key derivation. \n" 
	   "\t--target-time <float>: total time (sec) for key derivation. A " 
	   "larger value provides more security for a weak password. A strong key which contains high "
	   "entropy does not affect by this option, since it will not be derivated more than 1 "
	   "pass by default. To disable this behavior, use \"--no-detect-entropy\"\n"
	   "\t--target-level <int>: max derivation level for this passphrase."
	   "\t--no-detect-entropy: run full key derivation process regardless of the passphrase/keyfile's estimate entropy. may increase "
	   "unlock time when the key/keyfile itself is entropy-rich, which is enough to "
	   "ensure security without the key derivation process (e.g. random generated passphrase).\n"
	   "\t--anonymous-key: create an anonymous key. An anonymous key will be removed using AddKey without "
	   "\"--rapid-add\". This is designed for users that requires enhanced protection under scenario where untrust "
	   "entities are allowed to unlock the device. Non-anonymized passphrase would be more easily brute-forced "
	   "to acquire the original passphrase via the identifiers recorded in the metadata area.\n"));
};

void frontend_help(const char *the_3rd_argv) {
   if (!the_3rd_argv) {
      printf(_("usage: \"windham <action> <target>\"\n"
               "possible actions are:  'Open'  'Close'  'New'  'AddKey'  'DelKey' 'Backup' 'Restore' 'Suspend' 'Resume' and 'Destory'\n\n"
               "Use command \"windham Help <action>\" to view specific help text for each action.\n\n"
               "pre-compiled arguments. These arguments serve an informative purpose; changing them may render your "
               "device inaccessible.\n"));
      printf(_("\nVersion:\n"));
      printf(_("\tWindham version: %s\n"), VERSION);
      printf(_("\tWindham header metadata version: %i\n"), WINDHAM_METADATA_VERSION);
      printf(_("\tTarget kernel version for this build: %s\n"), TARGET_KERNEL_VERSION);
      
      printf(_("\nFunctionality:\n"));
      printf(_("\tnumber of keyslots: %i\n"), KEY_SLOT_COUNT);
      printf(_("\tLength of the final encryption key (bits): %i\n"), HASHLEN * CHAR_BIT);
      printf(_("\tDefault block size: %d\n"), DEFAULT_BLOCK_SIZE);
      printf(_("\tFinal Header logical sector: %lu\n"), RAW_HEADER_AREA_IN_SECTOR);
      printf(_("\tPreset data start logical sector: %lu\n"), WINDHAM_FIRST_USEABLE_LGA);

      printf(_("\nSecutity:\n"));
#ifdef WINDHAM_NO_ENFORCE_SPEC_MITIGATION
      printf(_("\033[33mspeculation mitigation is disabled!\033[0m\n"));
#endif
#ifdef WINDHAM_ALLOW_ATTACH
      printf(_("\033[33mAllowing debugger to attach! This should be enabled only in debug mode.\033[0m\n"));
#endif
#ifdef CONFIG_USE_SWAP
      printf(_("\033[33mSwap space is used by default. Turning swap space on and wipe memory off will expose your key to the "
               "attacker.\033[0m\n"));
#endif
#ifndef CONFIG_WIPE_MEMORY
      printf(_("\033[33mWipe memory disabled.\033[0m\n"));
#endif
      printf(_("\tArgon2B3 memory size exponential count: %i\n"), KEY_SLOT_EXP_MAX);
      printf(_("\tArgon2B3 base memory size (KiB): %i\n"), BASE_MEM_COST);
      printf(_("\tArgon2B3 parallelism: %i\n"), PARALLELISM);
      printf(_("\tWipe memory for Argon2B3: %b\n"), (bool) ARGON2B3_CLEAR_INTERNAL_MEMORY);
      printf(_("\tDefault encryption target time: %i\n"), DEFAULT_TARGET_TIME);
      printf(_("\tDefault decryption target time (per slot): %i\n"), MAX_UNLOCK_TIME_FACTOR);
      printf(_("\tDefault encryption capped memory: %i\n"), DEFAULT_DISK_ENC_MEM_RATIO_CAP);
      printf(_("\tDefault encryption type: %s\n"), DEFAULT_DISK_ENC_MODE);

      printf(_("\nSystem and compiler information:\n"));
#ifdef __clang__
      printf(_("\tCompiler: Clang %d.%d.%d\n"), __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
      printf(_("\tCompiler: GCC %d.%d.%d\n"), __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
      printf(_("\tUnknown compiler\n"));
#endif
#if defined(CMAKE_VERSION)
      printf(_("\tSystem architecture: %s\n"), TARGET_ARCH);
      printf(_("\tSystem endianness: %s\n"), __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ? "Big": "Little");
      printf(_("\tBuild host Architecture: %s\n"), HOST_ARCH);
      printf(_("\tCompile time (GMT): %s\n"), CURRENT_TIME);
      printf(_("\tCMake version: %s\n"), CMAKE_VERSION);
#ifdef COMPILE_PARAMS
      printf(_("\n Compile Params: %s\n"), COMPILE_PARAMS);
#else
      printf(_("No Compile Params were givin, possibly debug build\n"));
#endif
#else // #if defined(CMAKE_VERSION)
      printf(_("Windham is not built by CMake, hence the system information is not avaliable.\n"));
#endif // #if defined(CMAKE_VERSION)
   } else if (strcmp("--license", the_3rd_argv) == 0) {
      printf(_("    Copyright (C) 2023 2024 2025 by \"level-128\" (W. Wang; mail: level-128@gmx.com)\n"
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
      printf(_("Open <target>: Unlock <target> and create a mapper (decrypted crypt device) under /dev/mapper/<location>. The key will be "
               "provided from the standard input.\n"
               "\n"
               "options:\n"
               "\t--to <name>: the target name of the mapper. The mapper will be named as <name>, locate under "
               "/dev/mapper/<name>\n"
               "\t--timeout <int>: set unlock timeout (sec, default = 0) for password re-prompt when open. Keys are stored in the Linux "
               "Kernel Key Retention service (keyring service).\n"
               "\t--dry-run: run without mapping the block device then print the master key and device parameters.\n"
               "\t--windhamtab-location <path>: Use a alternate windhamtab file instead of \"/etc/windhamtab\"\n"
               "\t--windhamtab-pass <int>: Only execute the givin pass in windhamtab file.\n"
               "\t--nokeyring: do not attempt to use keys in the Linux Kernel Key Retention service (keyring service).\n"
               "\t--readonly: Create read only mapper device.\n"
               "\t--allow-discards: Allow TRIM commands being sent to the crypt device.\n"
               "\t--no-read-workqueue: Process read requests synchronously by bypassing internal workqueue.\n"
               "\t--no-write-workqueue: Process write requests synchronously by bypassing internal workqueue.\n"
               "\t--no-map-partition: do not map the partition table that reside inside the crypt device after unlock.\n"));
      frontend_print_unlock_args();
      frontend_print_common_args();
   } else if (strcmp("Close", the_3rd_argv) == 0) {
      printf(_("Close <name> close the encrypt block device. the path of the device shoule be \"/dev/mapper/<name>\"\n"
	       "\n"
	       "options:\n"
	       "\t--defer: Defer closing the device until the device is free.\n"));
      frontend_print_common_args();
   }



   else if (strcmp("New", the_3rd_argv) == 0) {
      printf(_("New <target>: create a windham header on the device and add a new key. DO NOT COPY THE HEADER FROM OTHER ENCRYPTED "
               "DEVICES, BECAUSE THEY "
               "COULD BE UNLOCKED USING THE SAME MASTER KEY. \n"
               "\n"
               "options:\n"
               "\t--key <characters>: password input as argument instead of asking in the terminal interactively.\n"
               "\t--key-file <location>: password input as key file. The key file will be read as password (exclude EOF character). Option "
               "'--key' "
               "and '--key-file' are mutually exclusive\n"
	        "\t--keystdin: read key from standard input. the key format must be 32-byte bit stream encoded using hexadecimal format. "
            "spaces are ignored. Useful when intergrating with Clevis\n"
               "\t--encrypt-type <string>: designate an encryption scheme for the new header instead of the default one. It is not "
               "recommended nor necessary to do so, unless"
               " you have a specific reason. the encryption scheme should obey the format: \"*cipher*-*chainmode*-*ivmode*\".\n"
               "\t--block-size <int>: designate the encryption sector size. Size must be 512, 1024, 2048 or 4096.\n"
               "\t--decoy-size: Create a decoy partition instead; designate a size for decoy partition.\n"));
      frontend_print_newpw_args();
      frontend_print_common_args();
      printf(_("A list of supported encryption mode on your system is located at file \"/proc/crypto\". If the provided encryption "
               "scheme contains an unsupported "
               "but valid mode, a warning will appear that indicates the partition cannot be opened using your system.\n"));

   } else if (strcmp("AddKey", the_3rd_argv) == 0) {
      printf(_("AddKey <target>: Add a new key or passphrase to the existing windham header. The new passphrase will be asked after a "
               "successful unlock from "
               "the given key or passphrase.\n"
               "\n"
               "options:\n"
               "\t--generate-random-key: generate a random key that can only be unlocked using --keystdin; then print this key to stdout. "
               "It is designed to incorporate with clevis.\n"
               "\t--rapid-add: adding a key faster by not recalculating the keypool and header vector.\n"));
      frontend_print_unlock_args();
      frontend_print_newpw_args();
      frontend_print_common_args();
            printf(_(
            "\nEach AddKey will \"transform\" the Windham partition header by default. to \"transform\" a header means to convert "
            "the header into an equivalent form while changing most of its bytes to hide the detail of each transaction. "
            "Without the key, there is no clue to deduce whether two headers are equivalent (but you might just looking "
	    "for the UUID to conclude, but this is not deterministic, and the key here is to protect the passphrase) or whether a header is "
            "valid. This is a feature which designed to prevent adversaries who can access the device before and after each transaction. "
	    "If they could, they will be informed by the changing portion, then the possible key space will be dramatically shrinked since "
	    "only a tiny fraction of keys are possible to produce a designate changing portion. "
 "However, the transform time is proportional to the "
	    "enrolled passphrases: that is why option \"--rapid-add\" exists. \"--rapid-add\" is always safe if such adversaries does "
	    "not exist under your threat model.\n"));
   } else if (strcmp("DelKey", the_3rd_argv) == 0) {
      printf(_("DelKey <target>: remove a existing key or passphrase from the header.\n"
               "\n"
               "options:\n"
               "\t--anonymous-key: turning a non anonymous key to anonymous key.\n"
	       "\t--no-fill-pattern: Not filling random pattern after this action. "));
      frontend_print_unlock_args();
      frontend_print_common_args();
   } else if (strcmp("Backup", the_3rd_argv) == 0) {
      printf(_("Backup <target>: Backup the header into a separate file.\n"
               "\n"
               "options:\n"
               "\t--to <location>: REQUIRED; the location of the file.\n"));
      frontend_print_common_args();
   } else if (strcmp("Restore", the_3rd_argv) == 0) {
      printf(_("Restore <target>: Restore the header from a file to the device.\n"
               "\n"
               "options:\n"
               "\t--to <location>: REQUIRED; the location of the file.\n"));
      frontend_print_common_args();
   } else if (strcmp("Suspend", the_3rd_argv) == 0) {
      printf(_("Suspend <target>: Make device identifiable and accessible without password. When Suspending, only "
	       "action \"Open\" and \"Close\" could be used.\n"
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
   } else if (strcmp("Destory", the_3rd_argv) == 0) {
      printf(_("Destory <target>: Wipe the windham partition header.\n"
               "\n"));
   } else {
      print_error("<action> not recognized. type 'windham Help' to view help");
   }
   exit(0);
}
