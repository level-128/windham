#ifndef INCL_BKLIBHELP
#define INCL_BKLIBHELP

#include <limits.h>
#include "../libsrc/srclib.c"

void frontend_print_unlock_args() {

   printf(
      _("\nUnlock options:\n"
      "\t--key <string>:          password input as argument instead of asking interactively.\n"
      "\t--key-file <path>:       read password from a key file (excludes EOF). Mutually exclusive\n"
      "\t                         with --key and --keystdin.\n"
      "\t--keystdin:              read 32-byte hex-encoded key from standard input. Spaces ignored.\n"
      "\t                         Useful when integrating with Clevis.\n"
      "\t--master-key <hex>:      use master key (32 hex bytes) to unlock directly.\n"
      "\t--decoy:                 operate on a decoy partition.\n"
      "\t--max-unlock-memory <n>: total max memory (KiB) available for unlock KDF.\n"
      "\t--max-unlock-time <n>:   max unlock time (sec); use \"-\" for unlimited.\n"
      "\t--max-unlock-level <n>:  max KDF derivation level for unlock.\n"
      "\t--allow-swap:            allow allocation from swap space for KDF. Only physical memory\n"
      "\t                         is used by default. DO NOT enable if swap stores plaintext!\n"
      "\t--systemd-dialog:        use systemd password dialog for interactive input.\n")
      );
#ifndef CFG_USE_SWAP
   print_warning(_("--allow-swap disabled by compile configuration."));
#endif
}


void frontend_print_common_args() {
   printf(
      _(
          "\nCommon options:\n"
          "\t--no-admin:          skip root-privilege check.\n"
          "\t--yes:               skip confirmation prompts.\n"
          "\t--nofail:            exit normally when target device does not exist.\n"
          "\t--help:              print this help message.\n"
          "\t--print-debug:       enable debug output.\n"
          "\t--decrypt=<file>:    use full-disk-decrypt driver, write to <file>.\n"
          "\t--print-encryption:  use print driver (no-op, displays operations).\n"));
}

void frontend_print_newpw_args() {
   printf(
      _(
         "\nNew passphrase (KDF) options:\n"
         "\t--target-memory <n>:    total max memory (KiB) for key derivation.\n"
         "\t--target-time <n>:      target time (sec) for key derivation. Larger values\n"
         "\t                        strengthen weak passwords. High-entropy keys are not\n"
         "\t                        derived beyond 1 pass by default; use --no-detect-entropy\n"
         "\t                        to override.\n"
         "\t--target-level <n>:     max KDF derivation level for this passphrase.\n"
         "\t--no-detect-entropy:    run full KDF regardless of password entropy estimate.\n"
         "\t--anonymous-key:        store an anonymous key (no identifier in metadata).\n"
         "\t                        Anonymous keys are removed by AddKey without --rapid-add\n"
         "\t                        and resist brute-force identification better.\n"
         "\t--allow-swap:           allow KDF to allocate from swap space.\n"));
}

void frontend_help(const char * the_3rd_argv) {
   if (! the_3rd_argv) {
      printf(
         _(
            "usage: \"windham <action> <target>\"\n"
            "possible actions are:  'Open'  'Close'  'New'  'AddKey'  'DelKey'  'Backup'  'Restore'\n"
            "                       'Suspend'  'Resume'  'Destroy'  'Bench'  'Aux'  'Probe'  'List'\n\n"
            "Use command \"windham Help <action>\" to view specific help text for each action.\n\n"
            "pre-compiled arguments. These arguments serve an informative purpose; changing them may render your "
            "device inaccessible.\n"));
      printf(_("\nVersion:\n"));
      printf(_("\tWindham version: %s\n"), WINDHAM_VERSION);
      printf(_("\tWindham header metadata version: %i\n"), WINDHAM_METADATA_VERSION);
#ifdef WINDHAM_PLAT_GNU_LINUX
      printf(_("\tTarget Linux kernel version for this build: %s\n"), CMAKE_TARGET_KERNEL_VERSION);
#endif


      printf(_("\nSecutity:\n"));
      int issue_count = 0;
#ifdef WINDHAM_NO_ENFORCE_SPEC_MITIGATION
      printf(_("\033[33mspeculation mitigation not enforced!\033[0m\n"));
   	issue_count++;
#endif
#ifdef WINDHAM_NO_DISABLE_ATTACH
      printf(_("\033[33mAllowing debugger to attach! This should be enabled only in debug mode.\033[0m\n"));
   	issue_count++;
#endif
#ifdef CFG_USE_SWAP
      printf(_("\033[33mSwap space is used by default. Turning swap space on and wipe memory off will expose your key to the "
               "attacker.\033[0m\n"));
   	issue_count++;
#endif
#if ARGON2_CLEAR_INTERNAL_MEMORY == 0
      printf(_("\033[33mWipe memory disabled.\033[0m\n"));
      issue_count ++;
#endif
      if (issue_count == 0) {
         printf(_("All security enhancements have been enabled.\n"));
      }

      printf(_("\nFunctionality:\n"));
#if defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)
   	printf(_("\tMultithread Support: No\n"));
#else
      printf(_("\tMultithread Support: Yes\n"));
#endif
      printf(_("\tnumber of keyslots: %i\n"), KEY_SLOT_COUNT);
      printf(_("\tEntropy of the final encryption key (bits): %i\n"), HASHLEN * CHAR_BIT);
      printf(_("\tDefault block size: %d\n"), DEFAULT_BLOCK_SIZE);
      printf(_("\tFinal Header logical sector (header size / 512b): %"PRIu64"\n"), (uint64_t)RAW_HEADER_AREA_IN_SECTOR);
      printf(_("\tArgon2B3 memory size exponential count: %i\n"), KEY_SLOT_EXP_MAX);
      printf(_("\tArgon2B3 base memory size (KiB): %i\n"), BASE_MEM_COST);
      printf(_("\tArgon2B3 parallelism: %i\n"), PARALLELISM);
      printf(_("\tDefault encryption target time: %f\n"), DEFAULT_TARGET_TIME);
      printf(_("\tDefault decryption target time (per slot): %i\n"), MAX_UNLOCK_TIME_FACTOR);
      printf(_("\tDefault encryption capped memory: %i\n"), DEFAULT_DISK_ENC_MEM_RATIO_CAP);
      printf(_("\tDefault encryption type: %s\n"), DEFAULT_DISK_ENC_MODE);
#ifdef WINDHAM_UTF_32
      printf(_("\tchar32_t encoding:       UTF-32\n"));
#else
      printf(_("\tchar32_t encoding:       unspecified, system reduced to ASCII support!\n"));
#endif
      printf(_("\nSystem and compiler information:\n"));
#ifdef __clang__
      printf(_("\tCompiler: Clang %d.%d.%d\n"), __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
      printf(_("\tCompiler: GCC %d.%d.%d\n"), __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
      printf(_("\tUnknown compiler\n"));
#endif
#ifdef CMAKE_COMPILE_PARAMS
      printf(_("\tCompile Params: %s\n"), CMAKE_COMPILE_PARAMS);
#endif
#if defined(WINDHAM_USING_CMAKE)
      printf(_("\tSystem architecture: %s\n"), CMAKE_TARGET_ARCH);
      printf(
         _("\tSystem endianness: %s\n"),
         __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            ? "Big"
            : "Little");
      printf(_("\tBuild host Architecture: %s\n"), CMAKE_HOST_ARCH);
      printf(_("\tCompile time (GMT): %s\n"), CMAKE_BUILD_TIME);
      printf(_("\tCMake version: %s\n"), WINDHAM_USING_CMAKE);

#else // #if defined(WINDHAM_USING_CMAKE)
      printf(_("Windham is using ISO C profile, hence the system information is not avaliable.\n"));
#endif // #if defined(WINDHAM_USING_CMAKE)
   } else if (strcmp("--license", the_3rd_argv) == 0) {
      printf(
         _(
            "    Copyright (C) 2023 2024 2025 by \"level-128\" (mail: level-128@gmx.com)\n"
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
      printf(
         _(
            "Open <target>: Unlock a Windham partition and create a decrypted mapper device\n"
            "under /dev/mapper/<name>. The key is provided interactively unless --key,\n"
            "--key-file, or --keystdin is used. If <target> is \"TAB\", entries from\n"
            "/etc/windhamtab (or --windhamtab-location) are processed.\n"
            "\n"
            "options:\n"
            "\t--to <name>:               mapper target name under /dev/mapper/<name>.\n"
            "\t                            Default: windham-<UUID>.\n"
            "\t--timeout <sec>:            keyring timeout; stores disk key in kernel keyring\n"
            "\t                            for re-open without password (0 = no keyring).\n"
          "\t--dry-run:                  unlock and validate, but do not create mapper.\n"
          "\t                            Prints master key and device parameters.\n"
          "\t--show-master-key:          unlock and print the hex-encoded master key;\n"
          "\t                            exits without creating a mapper.  Mutually\n"
          "\t                            exclusive with --dry-run.\n"
            "\t--windhamtab-location <p>:  use alternate windhamtab file path.\n"
            "\t--windhamtab-pass <n>:      execute only the specified pass number from\n"
            "\t                            windhamtab.\n"
            "\t--nokeyring:                do not use kernel key retention service.\n"
            "\t--readonly:                 create read-only mapper device.\n"
            "\t--allow-discards:           allow TRIM/DISCARD passthrough to crypt device.\n"
            "\t--no-read-workqueue:        bypass dm-crypt read workqueue (lower latency).\n"
            "\t--no-write-workqueue:       bypass dm-crypt write workqueue.\n"
            "\t--no-map-partition:         do not map partition table inside crypt device.\n"
            "\t--no-aux:                   do not probe or print aux entries after unlock.\n"
            "\t--aux-link[=paths]:         restrict linked-partition UUID resolution to the\n"
            "\t                             given comma-separated device paths instead of\n"
            "\t                             scanning /proc/partitions. Without a value,\n"
            "\t                             the default system-wide scan is used.\n"));
      frontend_print_unlock_args();
      frontend_print_common_args();
   } else if (strcmp("Close", the_3rd_argv) == 0) {
      printf(
         _(
            "Close <name>: Close (remove) an active dm-crypt mapper device. The name\n"
            "refers to the entry under /dev/mapper/<name>.\n"
            "\n"
            "options:\n"
            "\t--defer: defer removal until the device is no longer in use.\n"
            "\t--all:   close all active Windham mapper devices.\n"));
      frontend_print_common_args();
   } else if (strcmp("New", the_3rd_argv) == 0) {
      printf(
         _(
            "New <target>: Create a Windham header on <target> and enroll an initial\n"
            "passphrase. DO NOT copy headers between devices — they would share the\n"
            "same master key.\n"
            "\n"
            "options:\n"
            "\t--key <string>:       password as command-line argument.\n"
            "\t--key-file <path>:    read password from a key file. Mutually exclusive\n"
            "\t                       with --key and --keystdin.\n"
            "\t--keystdin:           read 32-byte hex key from standard input.\n"
            "\t--diskfile <size>:    create a sparse disk file of <size> bytes as target.\n"
            "\t                       Uses overcommit; only allocates blocks on write.\n"
            "\t--encrypt-type <s>:   encryption scheme: \"cipher-chainmode-ivmode\".\n"
            "\t                       Default: \"aes-xts-plain64\".\n"
            "\t--block-size <n>:     encryption sector size: 512, 1024, 2048, or 4096.\n"
            "\t--decoy-size <n>:     create a decoy partition of <n> MiB instead.\n"
             "\t--aux-sector-size <n>: size of the aux metadata zone, in 512-byte sectors.\n"
#ifndef CFG_NO_FF_CREATE
             "\t--create-exfat:       after creating the header, format the encrypted data\n"
             "\t                       area as an exFAT filesystem using FatFs.\n"
#endif
             ));
      frontend_print_newpw_args();
      frontend_print_common_args();
      printf(
         _(
            "\nSupported encryption modes are listed in /proc/crypto. If the chosen scheme\n"
            "is valid but unsupported on your kernel, a warning is issued — the partition\n"
            "will not be openable on this system.\n"));
   } else if (strcmp("AddKey", the_3rd_argv) == 0) {
      printf(
         _(
            "AddKey <target>: Enroll a new passphrase on an existing Windham partition.\n"
            "You must unlock with an existing passphrase first, then provide the new one.\n"
            "\n"
            "options:\n"
            "\t--new-key=<password>:     provide the new passphrase as a command-line\n"
            "\t                           argument instead of typing interactively.\n"
            "\t--generate-random-key:    generate a random 32-byte hex key, print to stdout,\n"
            "\t                           and enroll it. Designed for use with Clevis.\n"
            "\t--rapid-add:              skip header re-transform for speed.\n"
            "\t                           Safe when no adversary can observe the device\n"
            "\t                           between transactions.\n"
            "\t--anonymous-key:          enroll an anonymous key (no identifier stored).\n"));
      frontend_print_unlock_args();
      frontend_print_newpw_args();
      frontend_print_common_args();
   } else if (strcmp("DelKey", the_3rd_argv) == 0) {
      printf(
         _(
            "DelKey <target>: Remove a passphrase from the Windham header.\n"
            "The passphrase to remove must be provided via --key or interactive input.\n"
            "\n"
            "options:\n"
            "\t--anonymous-key:        convert the matching key to anonymous instead\n"
            "\t                         of removing it (key identifier is zeroed).\n"
            "\t--no-fill-pattern:      skip filling random pattern after deletion.\n"));
      frontend_print_unlock_args();
      frontend_print_common_args();
    } else if (strcmp("Backup", the_3rd_argv) == 0) {
      printf(
         _(
              "Backup <target>: Copy the Windham header to a backup file.\n"
              "\n"
              "Three modes (mutually exclusive):\n"
              "\n"
              "  ── DEFAULT (all) ──\n"
              "  Backup [--to <file>] <device>\n"
              "  Dumps the full ~20 KB header including all registered passwords.\n"
              "  Requires: device + key.\n"
              "\n"
              "  ── FOLD ──\n"
              "  Backup --fold --to <file> <device>\n"
              "  Exports only the keyslot unlocked by the provided key/password.\n"
              "  Produces an ~960‑byte file containing one Key_slot (144 B) + uuid,\n"
              "  salt, and metadata.  Use for paper recovery or QR encoding.\n"
              "  Requires: device + key + --to.\n"
              "\n"
              "  ── QR CODE ──\n"
              "  Two sub‑paths:\n"
              "\n"
              "  1) From device (live):   Backup --qrcode [<device>]\n"
              "     Unlocks the device, builds fold data in memory, encodes to\n"
              "     QR, and prints to terminal.  Also needs a key.\n"
              "     --qrcode=<bmp> saves a 1‑bit BMP file instead of terminal\n"
              "     output (██ blocks).\n"
              "\n"
              "  2) From existing fold file (offline):\n"
              "     Backup --qrcode --to <fold-file>\n"
              "     Reads a previously‑created fold backup (no device needed),\n"
              "     encodes its content to QR, and prints or saves as BMP.\n"
              "     --qrcode without --to and without device has no data source\n"
              "     and will error.  No key is required for offline encoding.\n"
              "\n"
              "  Typical paper‑recovery workflow:\n"
              "    1. Create fold:   Backup --fold --to recovery.bu <device>\n"
              "    2. Encode QR:     Backup --qrcode --to recovery.bu\n"
              "    3. Print terminal output or:  Backup --qrcode=qr.bmp --to recovery.bu\n"
              "\n"
              "Options:\n"
              "  --to <path>     Output file for fold/all modes.\n"
              "                  Input file for offline QR mode.\n"
              "  --fold          Create a compact single‑keyslot backup (960 B).\n"
              "  --qrcode[=<bmp>]  Encode as QR code.  Optional =path writes a BMP.\n"));
      frontend_print_unlock_args();
      frontend_print_common_args();
      frontend_print_unlock_args();
      frontend_print_common_args();
   } else if (strcmp("Restore", the_3rd_argv) == 0) {
      printf(
         _(
            "Restore <target>: Restore a Windham header from a backup file.\n"
            "\n"
            "    --to <path>    REQUIRED; source backup file.\n"
            "    --fold         Restore from a fold backup previously created\n"
            "                   with --fold.  Requires the passphrase or master\n"
            "                   key that was used to create the backup.\n"
            "\n"
            "IMPORTANT: Never clone a Windham device.  Restore always preserves\n"
            "the original sector range from the backup — restoring to a device\n"
            "of a different size will refuse to operate.  Two devices sharing the\n"
            "same disk encryption key is a catastrophic security risk.\n"));
      frontend_print_common_args();
   } else if (strcmp("Suspend", the_3rd_argv) == 0) {
      printf(
         _(
            "Suspend <target>: Clear the encryption keys from the header so the\n"
            "device can be opened without a password. In suspended state, only\n"
            "Open and Close are available. Use Resume to restore normal operation.\n"));
      frontend_print_unlock_args();
      frontend_print_common_args();
   } else if (strcmp("Resume", the_3rd_argv) == 0) {
      printf(
         _(
            "Resume <target>: Restore the encryption keys into the header so the\n"
            "device requires a password again. Reverses Suspend.\n"));
      frontend_print_unlock_args();
      frontend_print_common_args();
   } else if (strcmp("Bench", the_3rd_argv) == 0) {
      printf(
         _(
            "Bench: Run the Argon2 KDF benchmark to determine optimal unlock parameters.\n"));
      frontend_print_common_args();
   } else if (strcmp("Destory", the_3rd_argv) == 0) {
      printf(
         _(
            "Destory <target>: Wipe the Windham header from the device, permanently\n"
            "destroying all passphrase and encryption metadata.\n"
            "\n"
            "options:\n"
            "\t--decoy:  target is a decoy partition (header at GPT end).\n"));
      frontend_print_common_args();
   } else if (strcmp("Aux", the_3rd_argv) == 0) {
      printf(
         _(
            "Aux <target>: Manage auxiliary data entries stored in the aux zone of a\n"
            "Windham partition. Each entry is encrypted with a key derived from the\n"
            "keyslot used to unlock the device.\n"
            "\n"
            "Action options (exactly one required):\n"
            "\t--aux-add=<content>:       add a plaintext entry (multibyte/UTF-8 → char32_t).\n"
            "\t                             On platforms without WINDHAM_UTF_32, ASCII only.\n"
            "\t--aux-add-command=<cmd>:   add a SHELL command entry. Executed after all\n"
            "\t                             cascade links are opened. \"@\" in the command\n"
            "\t                             is replaced with comma-separated mapper names.\n"
            "\t--aux-add-link=<path>:     add a LINK_OPEN entry targeting another Windham\n"
            "\t                             partition at <path>. On Open, the linked device\n"
            "\t                             is automatically unlocked in cascade.\n"
            "\t--aux-del:                 delete all aux entries matching the current key.\n"
            "\t--aux-rm=<N>:              delete a single aux entry by its 1-based index as\n"
            "\t                             shown by --aux-probe.\n"
            "\t--aux-probe:               list all aux entries matching the current key,\n"
            "\t                             plus all public (unencrypted) entries.\n"
            "\n"
            "LINK_OPEN options (used with --aux-add-link):\n"
            "\t--aux-target-key=<pwd>:    password for the linked device (non-interactive).\n"
            "\t--aux-target-keyfile=<p>:  read linked device password from a key file.\n"
            "\t--aux-link-flag=SHORTCUT:  set STOP_EXEC_NEXT_IF_SUCC — if this link opens\n"
            "\t                             successfully, skip remaining sibling links at the\n"
            "\t                             same cascade level.\n"
            "\t--aux-link-prio=<0-255>:   set priority for ordering within this device's\n"
            "\t                             aux zone (default 128; lower = processed first).\n"
            "\n"
            "Shell options (used with --aux-add-command):\n"
            "\t--aux-flag=BLCKOPEN:       stop executing further aux entries if the command\n"
            "\t                             succeeds (STOP_EXEC_NEXT_IF_SUCC).\n"
            "\t--aux-timeout=<sec>:       max time to wait for the command (ISO C threads\n"
            "\t                             required; synchronously with a warning otherwise).\n"
            "\n"
            "Other options:\n"
            "\t--aux-type=<name>:         set entry type identifier for --aux-add.\n"));
      frontend_print_unlock_args();
       frontend_print_common_args();
    } else {
      print_error("<action> not recognized. type 'windham Help' to view help");
   }
   exit(0);
}
#endif
