#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "include/windham_const.h"
#include "include/getopt.h"

// gettext only works when frontend.c as cmake target
#ifndef IS_FRONTEND_ENTRY
#define _(STRING) STRING
#endif

#define DEFAULT_EXEC_DIR "/etc/windham"

#include "backend/bklibmain.c"
#include "libsrc/argon_bench.c"
#include "libplat/loopctl.c"


enum {
	/* ── Target / Key ─────────────────────────── */
	NMOBJ_to,
	NMOBJ_key,
	NMOBJ_key_file,
	NMOBJ_new_key,
	NMOBJ_master_key,

	/* ── KDF / Performance ────────────────────── */
	NMOBJ_max_unlock_mem,
	NMOBJ_max_unlock_time,
	NMOBJ_max_unlock_level,
	NMOBJ_target_mem,
	NMOBJ_target_time,
	NMOBJ_target_level,
	NMOBJ_unlock_timeout,

	/* ── Device creation ──────────────────────── */
	NMOBJ_encrypt_type,
	NMOBJ_block_size,
	NMOBJ_decoy_size,
	NMOBJ_disk_file_size,

	/* ── windhamtab ────────────────────────────── */
	NMOBJ_windhamtab_location,
	NMOBJ_windhamtab_pass,

	/* ── Aux zone ─────────────────────────────── */
	NMOBJ_aux_add,
	NMOBJ_aux_type,

	/* ── Bool flags: operation mode ───────────── */
	NMOBJ_key_stdin,
	NMOBJ_gen_randkey,
	NMOBJ_target_dry_run,
	NMOBJ_is_no_detect_entropy,
	NMOBJ_is_rapid_add,
	NMOBJ_is_anonymous_key,
	NMOBJ_is_no_fill_random_pattern,

	/* ── Bool flags: dm-crypt / device ────────── */
	NMOBJ_target_restore,
	NMOBJ_target_decoy,
	NMOBJ_target_readonly,
	NMOBJ_target_allow_discards,
	NMOBJ_target_no_read_workqueue,
	NMOBJ_target_no_write_workqueue,

	/* ── Bool flags: system / isolation ────────── */
	NMOBJ_is_allow_swap,
	NMOBJ_is_systemd,
	NMOBJ_is_nokeyring,
	NMOBJ_is_nofail,
	NMOBJ_is_noadmin,
	NMOBJ_is_no_map_partition,
	NMOBJ_is_deffered_remove,

	/* ── Bool flags: interaction ──────────────── */
	NMOBJ_yes,
	NMOBJ_print_debug,
	NMOBJ_use_printk,
	NMOBJ_help,

	/* ── Aux zone commands ────────────────────── */
	NMOBJ_aux_del,
	NMOBJ_aux_probe,
	NMOBJ_is_no_aux,
	NMOBJ_aux_add_command,
	NMOBJ_aux_flag,
	NMOBJ_aux_add_link,

	/* ── Probe ─────────────────────────────────── */
	NMOBJ_probe_dir,
	NMOBJ_probe_linux,
	NMOBJ_probe_pattern,

	/* ── LINK_OPEN ────────────────────────────── */
	NMOBJ_link_flag,
	NMOBJ_link_prio,
	NMOBJ_target_key,
	NMOBJ_target_key_file,
	NMOBJ_aux_link_paths,

	/* ── Misc ─────────────────────────────────── */
	NMOBJ_close_all,
	NMOBJ_aux_rm,
	NMOBJ_target_SIZE
};


const char *const actions[] = {
	"Help",
	"--help",
	"-h",
	"Open",
	"Close",
	"New",
	"AddKey",
	"DelKey",
	"Backup",
	"Restore",
	"Suspend",
	"Resume",
	"Destroy",
	"Bench",
	"Aux",
	"Probe",
	"List"
};

enum actions_type {
	NMOBJ_action_help = 0,
	NMOBJ_action_open = 3,
	NMOBJ_action_close,
	NMOBJ_action_new,
	NMOBJ_action_addkey,
	NMOBJ_action_delkey,
	NMOBJ_action_backup,
	NMOBJ_action_restore,
	NMOBJ_action_suspend,
	NMOBJ_action_resume,
	NMOBJ_action_destory,
	NMOBJ_action_bench,
	NMOBJ_action_aux,
	NMOBJ_action_probe,
	NMOBJ_action_list,
	NMOBJ_action_ALL = -1
};

int options[NMOBJ_target_SIZE] = {0};

const struct option long_options[] = {
	/* ── Target / Key (value) ─────────────────── */
	{"to", required_argument, &options[NMOBJ_to], 1},
	{"key", required_argument, &options[NMOBJ_key], 1},
	{"key-file", required_argument, &options[NMOBJ_key_file], 1},
	{"new-key", required_argument, &options[NMOBJ_new_key], 1},
	{"master-key", required_argument, &options[NMOBJ_master_key], 1},

	/* ── KDF / Performance (value) ────────────── */
	{"max-unlock-memory", required_argument, &options[NMOBJ_max_unlock_mem], 1},
	{"max-unlock-time", required_argument, &options[NMOBJ_max_unlock_time], 1},
	{"max-unlock-level", required_argument, &options[NMOBJ_max_unlock_level], 1},
	{"target-memory", required_argument, &options[NMOBJ_target_mem], 1},
	{"target-time", required_argument, &options[NMOBJ_target_time], 1},
	{"target-level", required_argument, &options[NMOBJ_target_level], 1},
	{"timeout", required_argument, &options[NMOBJ_unlock_timeout], 1},

	/* ── Device creation (value) ────────────────── */
	{"encrypt-type", required_argument, &options[NMOBJ_encrypt_type], 1},
	{"block-size", required_argument, &options[NMOBJ_block_size], 1},
	{"decoy-size", required_argument, &options[NMOBJ_decoy_size], 1},
	{"diskfile", required_argument, &options[NMOBJ_disk_file_size], 1},

	/* ── windhamtab (value) ────────────────────── */
	{"windhamtab-location", required_argument, &options[NMOBJ_windhamtab_location], 1},
	{"windhamtab-pass", required_argument, &options[NMOBJ_windhamtab_pass], 1},

	/* ── Aux zone (value) ──────────────────────── */
	{"aux-add", required_argument, &options[NMOBJ_aux_add], 1},
	{"aux-type", required_argument, &options[NMOBJ_aux_type], 1},

	/* ── Bool flags: operation mode ────────────── */
	{"keystdin", no_argument, &options[NMOBJ_key_stdin], 1},
	{"generate-random-key", no_argument, &options[NMOBJ_gen_randkey], 1},
	{"dry-run", no_argument, &options[NMOBJ_target_dry_run], 1},
	{"no-detect-entropy", no_argument, &options[NMOBJ_is_no_detect_entropy], 1},
	{"rapid-add", no_argument, &options[NMOBJ_is_rapid_add], 1},
	{"anonymous-key", no_argument, &options[NMOBJ_is_anonymous_key], 1},
	{"no-fill-pattern", no_argument, &options[NMOBJ_is_no_fill_random_pattern], 1},

	/* ── Bool flags: dm-crypt / device ─────────── */
	{"restore", no_argument, &options[NMOBJ_target_restore], 1},
	{"decoy", no_argument, &options[NMOBJ_target_decoy], 1},
	{"readonly", no_argument, &options[NMOBJ_target_readonly], 1},
	{"allow-discards", no_argument, &options[NMOBJ_target_allow_discards], 1},
	{"no-read-workqueue", no_argument, &options[NMOBJ_target_no_read_workqueue], 1},
	{"no-write-workqueue", no_argument, &options[NMOBJ_target_no_write_workqueue], 1},

	/* ── Bool flags: system / isolation ────────── */
	{"allow-swap", no_argument, &options[NMOBJ_is_allow_swap], 1},
	{"systemd-dialog", no_argument, &options[NMOBJ_is_systemd], 1},
	{"nokeyring", no_argument, &options[NMOBJ_is_nokeyring], 1},
	{"nofail", no_argument, &options[NMOBJ_is_nofail], 1},
	{"no-admin", no_argument, &options[NMOBJ_is_noadmin], 1},
	{"no-map-partition", no_argument, &options[NMOBJ_is_no_map_partition], 1},
	{"defer", no_argument, &options[NMOBJ_is_deffered_remove], 1},

	/* ── Bool flags: interaction ────────────────── */
	{"yes", no_argument, &options[NMOBJ_yes], 1},
	{"print-debug", no_argument, &options[NMOBJ_print_debug], 1},
	{"printk", no_argument, &options[NMOBJ_use_printk], 1},
	{"help", no_argument, &options[NMOBJ_help], 1},

	/* ── Aux zone commands ─────────────────────── */
	{"aux-del", no_argument, &options[NMOBJ_aux_del], 1},
	{"aux-probe", no_argument, &options[NMOBJ_aux_probe], 1},
	{"no-aux", no_argument, &options[NMOBJ_is_no_aux], 1},
	{"aux-add-command", required_argument, &options[NMOBJ_aux_add_command], 1},
	{"aux-flag", required_argument, &options[NMOBJ_aux_flag], 1},
	{"aux-add-link", required_argument, &options[NMOBJ_aux_add_link], 1},

	/* ── Probe ─────────────────────────────────── */
	{"dir", required_argument, &options[NMOBJ_probe_dir], 1},
	{"probe-linux", no_argument, &options[NMOBJ_probe_linux], 1},
	{"probe-pattern", required_argument, &options[NMOBJ_probe_pattern], 1},

	/* ── LINK_OPEN ─────────────────────────────── */
	{"aux-link-flag", required_argument, &options[NMOBJ_link_flag], 1},
	{"aux-link-prio", required_argument, &options[NMOBJ_link_prio], 1},
	{"aux-target-key", required_argument, &options[NMOBJ_target_key], 1},
	{"aux-target-keyfile", required_argument, &options[NMOBJ_target_key_file], 1},
	{"aux-link", optional_argument, &options[NMOBJ_aux_link_paths], 1},

	/* ── Misc ───────────────────────────────────── */
	{"all", no_argument, &options[NMOBJ_close_all], 1},
	{"aux-rm", required_argument, &options[NMOBJ_aux_rm], 1},
	{0, 0, 0, 0}
};

#define ALLOW_OPEN_COMMON						\
  NMOBJ_key, NMOBJ_key_stdin, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_max_unlock_mem, \
    NMOBJ_max_unlock_time, NMOBJ_max_unlock_level,			\
    NMOBJ_target_decoy, NMOBJ_is_systemd, NMOBJ_is_nofail, NMOBJ_is_allow_swap

#define ALLOW_COMMON NMOBJ_is_noadmin, NMOBJ_yes, NMOBJ_print_debug, NMOBJ_use_printk, NMOBJ_help


int frontend_check_actions(const char *input) {
	for (int i = 0; (size_t) i < sizeof(actions) / sizeof(char *); i++) {
		if (strcmp(actions[i], input) == 0) {
			if (0 <= i && i <= 2) {
				return NMOBJ_action_help;
			}
			return i;
		}
	}
	if (memcmp(input, "--", 2) == 0) {
		print_error(_("Arguments should locate after <action> and <target>."));
	}
	print_error(_("<action> %s not recognized. type 'windham Help' to view help"), input);
	exit(2);
}


noreturn void frontend_no_input() {
	printf(
		_(
			"Windham (%s) Copyright (C) 2023 2024 2025\n\n"

			"usage: \"windham <action> <target>\"\n"
			"For help, type 'windham Help' to view help for all possible actions\n\n"

			"This program comes with ABSOLUTELY NO WARRANTY; for details type 'Help --license'.\n"
			"This is free software, and you are welcome to redistribute it under certain conditions;\n"),
		WINDHAM_VERSION);
	exit(0);
}


int _sum_values(int first, ...) {
	int sum = 0;

	va_list args;
	va_start(args, first);

	int value = first;
	while (value != NMOBJ_target_SIZE) {
		sum += options[value];
		value = va_arg(args, int);
	}

	va_end(args);
	return sum;
}


void init_key_obj_and_master_key(Key *key, uint8_t master_key[HASHLEN], char *params[]) {
	if (options[NMOBJ_master_key]) {
		if (master_key_to_byte_array(params[NMOBJ_master_key], master_key) == false) {
			print_error(_("error when parsing master key: invalid length"));
		}
		key->key_or_keyfile_location = NULL;
		key->key_type = NMOBJ_key_file_type_masterkey;
		return;
	}
	memset(master_key, 0, HASHLEN);
	if (options[NMOBJ_key] == 1) {
		key->key_or_keyfile_location = params[NMOBJ_key];
		key->key_type = NMOBJ_key_file_type_key;
	} else if (options[NMOBJ_key_file] == 1) {
		key->key_or_keyfile_location = params[NMOBJ_key_file];
		key->key_type = NMOBJ_key_file_type_file;
	} else if (options[NMOBJ_is_systemd] == 1) {
		key->key_or_keyfile_location = NULL;
		key->key_type = NMOBJ_key_file_type_input_systemd;
	} else if (options[NMOBJ_key_stdin] == 1) {
		key->key_or_keyfile_location = NULL;
		key->key_type = NMOBJ_key_file_type_input_stdin;
	} else {
		key->key_or_keyfile_location = NULL;
		key->key_type = NMOBJ_key_file_type_input;
	}
}


void frontend_check_validity_and_execute(int action_num, const char *device, char *params[]) {
	uint8_t master_key[HASHLEN];
	int windhamtab_pass = 0;
	uintmax_t target_mem = SIZE_MAX;
	uintmax_t max_unlock_mem = SIZE_MAX;
	double target_time = DEFAULT_TARGET_TIME;
	double max_unlock_time = DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR;
	uintmax_t target_level = KEY_SLOT_EXP_MAX;
	int max_unlock_level = KEY_SLOT_EXP_MAX;
	uintmax_t timeout = 0;
	uintmax_t block_size = DEFAULT_BLOCK_SIZE;
	uintmax_t decoy_size = 0;
	uintmax_t disk_file_size = 0;
	char *windhamtab_location = NULL;
	char *encrypt_type = DEFAULT_DISK_ENC_MODE;


	bool is_root = is_running_as_root();

#if defined(IS_FRONTEND_ENTRY) && !defined(WINDHAM_TEST)
	if (!options[NMOBJ_is_noadmin]) {
		if (is_root == false) {
			print_error(_(
				"The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible "
				"without root permission"));
		}
	}
#endif

	// redirect the stdout to stderr for NMOBJ_gen_randkey. ISO C mode print to stdout withoud redirect.
#ifndef WINDHAM_ISOC
	if (options[NMOBJ_gen_randkey] == 1) {
		fflush(stdout);
		stdout_fd = dup(STDOUT_FILENO);
		dup2(STDERR_FILENO, STDOUT_FILENO);
	}
#endif

	char *end;

	if (options[NMOBJ_target_mem] == 1) {
		target_mem = strtoumax(params[NMOBJ_target_mem], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--target-memory");
		}
	}
	if (options[NMOBJ_target_time] == 1) {
		target_time = strtod(params[NMOBJ_target_time], &end);
		if (*end != '\0' || target_time < 0) {
			print_error(_("bad input for argument %s: not an positive value"), "--target-time");
		}
	}
	if (options[NMOBJ_target_level] == 1) {
		target_level = strtoumax(params[NMOBJ_target_level], &end, 10);
		if (*end != '\0' || target_level == 0) {
			print_error(_("bad input for argument %s: not an positive non-zero integer"), "--target-level");
		}
	}
	if (options[NMOBJ_max_unlock_mem] == 1) {
		max_unlock_mem = strtoumax(params[NMOBJ_max_unlock_mem], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--max-unlock-memory");
		}
	}
	if (options[NMOBJ_max_unlock_time] == 1) {
		if (strcmp(params[NMOBJ_max_unlock_time], "-") == 0) {
			max_unlock_time = DBL_MAX;
		} else {
			max_unlock_time = strtod(params[NMOBJ_max_unlock_time], &end);
			if (*end != '\0' || max_unlock_time < 0) {
				print_error(_("bad input for argument %s: not an positive value"), "--max-unlock-time");
			}
		}
	}
	if (options[NMOBJ_max_unlock_level] == 1) {
		const long res = strtol(params[NMOBJ_max_unlock_level], &end, 10);

		if (*end != '\0' || res < 0) {
			print_error(_("bad input for argument %s: not an positive non-zero integer"), "--max-unlock-level");
		} else if (res > KEY_SLOT_EXP_MAX) {
			print_error(_("Max unlock level exceeded possible value determined by format."));
		}
		max_unlock_level = (int) res;
	}

	if (options[NMOBJ_unlock_timeout] == 1) {
		timeout = strtoumax(params[NMOBJ_unlock_timeout], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--timeout");
		}
	}
	if (options[NMOBJ_windhamtab_pass] == 1) {
		const long res = strtol(params[NMOBJ_windhamtab_pass], &end, 10);
		if (*end != '\0') {
			print_error(_("bad input for argument %s: not an positive integer"), "--windhamtab-pass");
		} else if (res > INT_MAX || res < INT_MIN) {
			print_error(_("bad input for argument %s: value out of range"), "--windhamtab-pass");
		}
		windhamtab_pass = (int) res;
	}
	if (options[NMOBJ_block_size] == 1) {
		block_size = strtoull(params[NMOBJ_block_size], &end, 10);
		if (*end != '\0' || (block_size != 512 && block_size != 1024 && block_size != 2048 && block_size != 4096)) {
			print_error(_("bad input for argument --block-size: must be one of 512, 1024, 2048 or 4096"));
		}
	}

	if (options[NMOBJ_decoy_size] == 1) {
		decoy_size = parse_size(params[NMOBJ_decoy_size]);
	}

	if (options[NMOBJ_disk_file_size] == 1) {
		disk_file_size = parse_size(params[NMOBJ_disk_file_size]);
	}


	if (options[NMOBJ_windhamtab_location]) {
		windhamtab_location = params[NMOBJ_windhamtab_location];
	}

	if (options[NMOBJ_encrypt_type]) {
		encrypt_type = params[NMOBJ_encrypt_type];
	}

	// Done parsing the arguments.

#if defined(IS_FRONTEND_ENTRY) && !defined(WINDHAM_TEST)
	is_skip_conformation = options[NMOBJ_yes];
	print_debug_enable = options[NMOBJ_print_debug];
	use_printk = options[NMOBJ_use_printk];
	init(is_root);
#else
	is_skip_conformation = 1;
#endif

#ifndef CONFIG_USE_SWAP
	if (options[NMOBJ_is_allow_swap]) {
		print_error(_("--allow-swap is disabled from the compile option. Recompile to enable this feature."));
	}
#endif

	// ── Argument validation DSL (see include/valid_args.c) ──

#define need_dev(_action) \
   if (action_num == NMOBJ_action_##_action && device == NULL) \
      print_error(_("<target> not provided. type 'windham Help' to view help"));

#define need_dev_if(_action, _cond) \
   if (action_num == NMOBJ_action_##_action && device == NULL && (_cond)) \
      print_error(_("<target> not provided. type 'windham Help' to view help"));

#define opt_allow(_action, ...) \
   if (action_num == NMOBJ_action_##_action) { \
      const uint8_t _a[] = { __VA_ARGS__ }; \
      for (unsigned _i = 0; _i < NMOBJ_target_SIZE; _i++) { \
         if (options[_i] == 1) { \
            bool _ok = false; \
            for (unsigned _j = 0; _j < sizeof(_a); _j++) { \
               if (_a[_j] == _i) { _ok = true; break; } \
            } \
            if (!_ok) \
               print_error(_("argument --%s is not valid under action: %s"), \
                           (char *) long_options[_i].name, \
                           (char *) actions[action_num]); \
         } \
      } \
   }

#define ent(_action_num, _warn_or_err, _msg, _options) \
   if ((action_num == -1 || action_num == (NMOBJ_action_##_action_num)) && !(_options)) { \
    if (strcmp(#_warn_or_err, "warn") == 0) { \
      print_warning(_(_msg)); \
    } else if (strcmp(#_warn_or_err, "err") == 0) { \
      print_error(_(_msg)); \
    } \
  }

#define is(_x) (options[_x] == 1)
#define has(_cnt, ...) (_sum_values(__VA_ARGS__, NMOBJ_target_SIZE) <= _cnt)

#include "include/valid_args.c"

#undef need_dev
#undef need_dev
#undef need_dev_if
#undef opt_allow
#undef ent
#undef is
#undef has


	Key key;
	init_key_obj_and_master_key(&key, master_key, params);

	// execute
	// "Open", "Close", "New", "AddKey", "RevokeKey", "Backup", "Restore", "Suspend", "Resume"
	switch (action_num) {
		case NMOBJ_action_open:
			action_open_(
				device,
				windhamtab_location,
				params[NMOBJ_to],
				timeout,
				windhamtab_pass,
				key,
				master_key,
				max_unlock_mem,
				max_unlock_time,
				max_unlock_level,
				options[NMOBJ_is_allow_swap],
				options[NMOBJ_target_decoy],
				options[NMOBJ_target_dry_run],
				options[NMOBJ_target_readonly],
				options[NMOBJ_target_allow_discards],
				options[NMOBJ_target_no_read_workqueue],
				options[NMOBJ_target_no_write_workqueue],
				options[NMOBJ_is_no_map_partition],
				options[NMOBJ_is_nokeyring],
				options[NMOBJ_is_nofail],
				options[NMOBJ_windhamtab_pass],
				options[NMOBJ_is_no_aux],
				params[NMOBJ_aux_link_paths]);

			break;
		case NMOBJ_action_close:
			if (options[NMOBJ_close_all]) {
				action_close_all(options[NMOBJ_is_deffered_remove]);
			} else {
				action_close(device, options[NMOBJ_is_deffered_remove]);
			}
			break;
		case NMOBJ_action_new:
			init_device(device,
			            false,
			            false,
			            options[NMOBJ_is_nofail],
			            true,
			            options[NMOBJ_disk_file_size] ? disk_file_size : 0,
			            options[NMOBJ_disk_file_size] ? block_size : 0);

			action_create(
				STR_device->name,
				encrypt_type,
				key,
				target_mem,
				target_time,
				target_level,
				block_size,
				decoy_size,
				DEFAULT_AUX_SECTOR_SIZE,
				options[NMOBJ_is_no_detect_entropy],
				options[NMOBJ_is_anonymous_key],
				options[NMOBJ_is_allow_swap]);
			break;
		case NMOBJ_action_addkey:
			init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy], 0, 0);

			action_addkey(
				STR_device->name,
				key,
				master_key,
				max_unlock_mem,
				max_unlock_time,
				max_unlock_level,
				options[NMOBJ_is_allow_swap],
				options[NMOBJ_target_decoy],
				target_mem,
				target_time,
				target_level,
				options[NMOBJ_is_no_detect_entropy],
				options[NMOBJ_gen_randkey],
				options[NMOBJ_is_rapid_add],
				options[NMOBJ_is_anonymous_key],
				params[NMOBJ_new_key]);
			break;
		case NMOBJ_action_delkey:
			init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy], 0, 0);

			action_removekey(
				STR_device->name,
				key,
				master_key,
				max_unlock_mem,
				max_unlock_time,
				max_unlock_level,
				options[NMOBJ_is_allow_swap],
				options[NMOBJ_target_decoy],
				options[NMOBJ_is_anonymous_key],
				false);
			break;
		case NMOBJ_action_backup:
			init_device(device, false, true, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy], 0, 0);

			action_backup(STR_device->name,
			              params[NMOBJ_to],
			              options[NMOBJ_target_decoy], false);
			break;
		case NMOBJ_action_restore:
			init_device(device, false, true, options[NMOBJ_is_nofail], true, 0, 0);

			action_restore(STR_device->name, params[NMOBJ_to], options[NMOBJ_target_decoy]);
			break;
		case NMOBJ_action_suspend:
			init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy], 0, 0);

			action_suspend(
				STR_device->name,
				key,
				master_key,
				max_unlock_mem,
				max_unlock_time,
				max_unlock_level,
				options[NMOBJ_is_allow_swap],
				options[NMOBJ_target_decoy]);
			break;
		case NMOBJ_action_resume:
			init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy], 0, 0);
			action_resume(
				STR_device->name,
				key,
				master_key,
				max_unlock_mem,
				max_unlock_time,
				max_unlock_level,
				options[NMOBJ_is_allow_swap],
				options[NMOBJ_target_decoy]);
			break;
		case NMOBJ_action_destory:
			init_device(device, false, false, options[NMOBJ_is_nofail], true, 0, 0);
			action_destory(STR_device->name, options[NMOBJ_target_decoy]);
			break;
		case NMOBJ_action_aux: {
			init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy], 0, 0);

			// Exactly one of --add, --del, --probe must be specified
			int aux_action_count = options[NMOBJ_aux_add] + options[NMOBJ_aux_del] + options[NMOBJ_aux_probe]
				+ options[NMOBJ_aux_add_command] + options[NMOBJ_aux_add_link] + options[NMOBJ_aux_rm];
			if (aux_action_count == 0) {
				print_error(_("Aux action requires one of --add, --del, --probe, --add-command, --add-link, or --aux-rm"));
			}
			if (aux_action_count > 1) {
				print_error(_("Only one aux sub-action can be specified at a time"));
			}

			if (options[NMOBJ_aux_add]) {
				action_aux_add(
					STR_device->name,
					key,
					master_key,
					max_unlock_mem,
					max_unlock_time,
					max_unlock_level,
					options[NMOBJ_is_allow_swap],
					options[NMOBJ_target_decoy],
					params[NMOBJ_aux_add]);
			} else if (options[NMOBJ_aux_add_command]) {
				action_aux_add_command(
					STR_device->name,
					key,
					master_key,
					max_unlock_mem,
					max_unlock_time,
					max_unlock_level,
					options[NMOBJ_is_allow_swap],
					options[NMOBJ_target_decoy],
					params[NMOBJ_aux_add_command],
					params[NMOBJ_aux_flag]);
			} else if (options[NMOBJ_aux_add_link]) {
				action_aux_add_link(
					STR_device->name,
					key,
					master_key,
					max_unlock_mem,
					max_unlock_time,
					max_unlock_level,
					options[NMOBJ_is_allow_swap],
					options[NMOBJ_target_decoy],
					params[NMOBJ_aux_add_link],
					params[NMOBJ_target_key],
					params[NMOBJ_target_key_file],
					params[NMOBJ_link_flag],
					params[NMOBJ_link_prio]);
			} else if (options[NMOBJ_aux_del]) {
				action_aux_del(
					STR_device->name,
					key,
					master_key,
					max_unlock_mem,
					max_unlock_time,
					max_unlock_level,
					options[NMOBJ_is_allow_swap],
					options[NMOBJ_target_decoy]);
			} else if (options[NMOBJ_aux_probe]) {
				action_aux_probe(
					STR_device->name,
					key,
					master_key,
					max_unlock_mem,
					max_unlock_time,
					max_unlock_level,
					options[NMOBJ_is_allow_swap],
					options[NMOBJ_target_decoy]);
			} else if (options[NMOBJ_aux_rm]) {
				long idx = strtol(params[NMOBJ_aux_rm], NULL, 10);
				if (idx < 1) {
					print_error(_("--aux-rm index must be a positive integer"));
				}
				action_aux_rm(
					STR_device->name,
					key,
					master_key,
					max_unlock_mem,
					max_unlock_time,
					max_unlock_level,
					options[NMOBJ_is_allow_swap],
					options[NMOBJ_target_decoy],
					(int)idx);
			}
			break;
		}
		case NMOBJ_action_probe: {
			const char *dir_path = params[NMOBJ_probe_dir];
			bool probe_linux = options[NMOBJ_probe_linux];
			const char *pattern = params[NMOBJ_probe_pattern];

#ifndef WINDHAM_ISOC
			if (!dir_path && !probe_linux) {
				probe_linux = true;
			}
#else
			if (!dir_path && !probe_linux) {
				print_error(_("Probe requires either --dir or --probe-linux"));
			}
			if (dir_path && probe_linux) {
				print_error(_("--dir and --probe-linux are mutually exclusive"));
			}
#endif
			action_probe(dir_path, probe_linux, pattern);
			break;
		}
		case NMOBJ_action_list: {
			action_list();
			break;
		}
		default:
			break;
	}
	windham_exit(0);
}

int main_(int argc, char *argv[]) {
	STR_device = malloc(sizeof(Device));
	environ = malloc(sizeof(char *));
	*environ = NULL;

	// initialize STR_device
	STR_device->block_count = -1;
	STR_device->block_size = -1;
	STR_device->is_loop = false;


	if (argc == 1) {
		frontend_no_input();
	}


	const int action_num = frontend_check_actions(argv[1]);
	if (action_num == NMOBJ_action_help) {
		frontend_help(
			argc > 2
				? argv[2]
				: NULL);
	}

	if (argc == 2) {
		if (action_num == NMOBJ_action_bench) {
			benchmark();
		} else {
			// DSL need_dev rules validate which actions require a device.
			char *params[NMOBJ_target_SIZE] = {NULL};
			frontend_check_validity_and_execute(action_num, NULL, params);
		}
	}
	if (argc >= 3) {
		char *params[NMOBJ_target_SIZE] = {NULL};

		// ── Phase 1: pre-scan for --help anywhere ─────────────────
		// This short-circuits before any real parsing. getopt_long will also
		// catch --help (see post-parse check below), but doing it here avoids
		// the device-resolution step when the user just wants help text.
		for (int i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
				frontend_help(argv[1]);
			}
		}

		// ── Phase 2: locate the device argument ────────────────────
		// Before this change, the device was required at argv[2] and any
		// --option appearing before it was an error.  Now we scan argv[2..]
		// to find the device wherever it appears, then rearrange argv so
		// that getopt_long sees options-only from argv[3] onward.
		//
		// Distinguishing the device from an option value:
		//   --key=pass        ← value is embedded (contains '=')
		//   --key pass        ← value is the next arg (no '=' in the option)
		//   /dev/sda          ← device (no preceding bare --option)
		//
		// If the preceding arg is a known long option that takes
		// required_argument AND has no '=', the current arg is its value,
		// not the device.
		int device_pos = -1;
		for (int i = 2; i < argc; i++) {
			if (argv[i][0] == '-') continue;

			bool is_option_val = false;
			if (i > 2 && argv[i - 1][0] == '-' && argv[i - 1][1] == '-') {
				const char *optname = argv[i - 1] + 2;  // skip "--"
				if (strchr(optname, '=') == NULL) {     // no embedded value
					for (size_t j = 0; j < sizeof(long_options) / sizeof(long_options[0]) - 1; j++) {
						if (strcmp(optname, long_options[j].name) == 0
						    && long_options[j].has_arg == required_argument) {
							is_option_val = true;
							break;
						}
					}
				}
			}

			if (!is_option_val) { device_pos = i; break; }
		}

		// ── Phase 3: rearrange argv → device at [2], options at [3..] ──
		// Example: argv = [windham, Open, --key, pass, /dev/sda]
		//   device_pos = 4
		//   memmove shifts argv[2..3] → argv[3..4], then puts /dev/sda at [2]
		//   result: [windham, Open, /dev/sda, --key, pass]
		// If device_pos == 2, no move needed (user already put device first).
		// If no device found at all, options start at argv[2].
		const char *device = NULL;
		int optind_start = 2;
		if (device_pos >= 0) {
			if (device_pos > 2) {
				char *tmp = argv[device_pos];
				memmove(&argv[3], &argv[2],
				        (size_t)(device_pos - 2) * sizeof(char *));
				argv[2] = tmp;
			}
			device = argv[2];
			optind_start = 3;
		}
		// Whether the action actually requires a device is checked
		// later by the DSL in valid_args.c (need_dev rules).

		// ── Phase 4: parse options via getopt_long ─────────────────
		int opt;
		int long_index = 0;
		optind = optind_start;
		opterr = 0;

		memset(options, 0, sizeof(options));
		while ((opt = getopt_long(argc, argv, "", long_options, &long_index)) != -1) {
			if (opt == '?') {
				print_error(_("Unknown option for %s"), argv[optind - 1]);
			} else if (opt == ':') {
				print_error(_("missing parameter for %s"), argv[optind - 1]);
			} else {
				params[long_index] = optarg;
			}
		}
		if (options[NMOBJ_help]) {
			frontend_help(argv[1]);
		}
		frontend_check_validity_and_execute(action_num, device, params);
	}
	free(STR_device);
	free(environ);
	return 0;
}
