#include "windham_const.h"
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

// gettext only works when frontend.c as cmake target
#ifndef _
#define _(STRING) STRING
#endif

#define DEFAULT_EXEC_DIR "/etc/windham"

#include "backend/bklibmain.c"
#include "library_intrnlsrc/argon_bench.c"
#include "library_intrnlsrc/libloop.c"


enum {
  NMOBJ_to,
  NMOBJ_key,
  NMOBJ_key_file,
  NMOBJ_master_key,
  NMOBJ_max_unlock_mem,
  NMOBJ_max_unlock_time,
  NMOBJ_max_unlock_level,
  NMOBJ_target_mem,
  NMOBJ_target_time,
  NMOBJ_target_level,
  NMOBJ_unlock_timeout,
  NMOBJ_encrypt_type,
  NMOBJ_block_size,
  NMOBJ_decoy_size,
  NMOBJ_windhamtab_location,
  NMOBJ_windhamtab_pass,
  NMOBJ_key_stdin,
  NMOBJ_gen_randkey,
  NMOBJ_target_dry_run,
  NMOBJ_is_no_detect_entropy,
  NMOBJ_is_rapid_add,
  NMOBJ_is_anonymous_key,
  NMOBJ_is_no_fill_random_pattern,
  NMOBJ_target_restore,
  NMOBJ_target_decoy,
  NMOBJ_target_readonly,
  NMOBJ_target_allow_discards,
  NMOBJ_target_no_read_workqueue,
  NMOBJ_target_no_write_workqueue,
  NMOBJ_is_allow_swap,
  NMOBJ_is_systemd,
  NMOBJ_is_nokeyring,
  NMOBJ_is_nofail,
  NMOBJ_is_noadmin,
  NMOBJ_is_no_map_partition,
  NMOBJ_is_deffered_remove,
  NMOBJ_yes,
  NMOBJ_print_debug,
  NMOBJ_help,
  NMOBJ_target_SIZE
};


const char * const actions[] = {
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
  "Bench"};

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
  NMOBJ_action_ALL = -1
};

int options[NMOBJ_target_SIZE] = {0};

const struct option long_options[] = {
  {"to", required_argument, &options[NMOBJ_to], 1},
  {"key", required_argument, &options[NMOBJ_key], 1},
  {"key-file", required_argument, &options[NMOBJ_key_file], 1},
  {"master-key", required_argument, &options[NMOBJ_master_key], 1},
  {"max-unlock-memory", required_argument, &options[NMOBJ_max_unlock_mem], 1},
  {"max-unlock-time", required_argument, &options[NMOBJ_max_unlock_time], 1},
  {"max-unlock-level", required_argument, &options[NMOBJ_max_unlock_level], 1},
  {"target-memory", required_argument, &options[NMOBJ_target_mem], 1},
  {"target-time", required_argument, &options[NMOBJ_target_time], 1},
  {"target-level", required_argument, &options[NMOBJ_target_level], 1},
  {"timeout", required_argument, &options[NMOBJ_unlock_timeout], 1},
  {"encrypt-type", required_argument, &options[NMOBJ_encrypt_type], 1},
  {"block-size", required_argument, &options[NMOBJ_block_size], 1},
  {"decoy-size", required_argument, &options[NMOBJ_decoy_size], 1},
  {"windhamtab-location", required_argument, &options[NMOBJ_windhamtab_location], 1},
  {"windhamtab-pass", required_argument, &options[NMOBJ_windhamtab_pass], 1},

  {"keystdin", no_argument, &options[NMOBJ_key_stdin], 1},
  {"generate-random-key", no_argument, &options[NMOBJ_gen_randkey], 1},
  {"dry-run", no_argument, &options[NMOBJ_target_dry_run], 1},
  {"no-detect-entropy", no_argument, &options[NMOBJ_is_no_detect_entropy], 1},
  {"rapid-add", no_argument, &options[NMOBJ_is_rapid_add], 1},
  {"anonymous-key", no_argument, &options[NMOBJ_is_anonymous_key], 1},
  {"no-fill-pattern", no_argument, &options[NMOBJ_is_no_fill_random_pattern], 1},
  {"restore", no_argument, &options[NMOBJ_target_restore], 1},
  {"decoy", no_argument, &options[NMOBJ_target_decoy], 1},
  {"readonly", no_argument, &options[NMOBJ_target_readonly], 1},
  {"allow-discards", no_argument, &options[NMOBJ_target_allow_discards], 1},
  {"no-read-workqueue", no_argument, &options[NMOBJ_target_no_read_workqueue], 1},
  {"no-write-workqueue", no_argument, &options[NMOBJ_target_no_write_workqueue], 1},
  {"allow-swap", no_argument, &options[NMOBJ_is_allow_swap], 1},
  {"systemd-dialog", no_argument, &options[NMOBJ_is_systemd], 1},
  {"nokeyring", no_argument, &options[NMOBJ_is_nokeyring], 1},
  {"nofail", no_argument, &options[NMOBJ_is_nofail], 1},
  {"no-admin", no_argument, &options[NMOBJ_is_noadmin], 1},
  {"no-map-partition", no_argument, &options[NMOBJ_is_no_map_partition], 1},
  {"defer", no_argument, &options[NMOBJ_is_deffered_remove], 1},
  {"yes", no_argument, &options[NMOBJ_yes], 1},
  {"help", no_argument, &options[NMOBJ_help], 1},
  {0, 0, 0, 0}};

#define CHECK_ALLOWED_OPEN						\
  NMOBJ_key, NMOBJ_key_stdin, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_max_unlock_mem, \
    NMOBJ_max_unlock_time, NMOBJ_max_unlock_level,			\
    NMOBJ_target_decoy, NMOBJ_is_systemd, NMOBJ_is_nofail, NMOBJ_is_allow_swap

#define CHECK_COMMON NMOBJ_is_noadmin, NMOBJ_yes, NMOBJ_print_debug, NMOBJ_help


#define check_action(...)						\
  const uint8_t check_allowed[] = __VA_ARGS__;				\
  for (unsigned i = 0; i < NMOBJ_target_SIZE; i++){			\
    if (options[i] == 1){						\
      bool is_okay = false;						\
      for (unsigned j = 0; j < sizeof(check_allowed); j++){		\
	if (check_allowed[j] == i){					\
	  is_okay = true;						\
	  break;							\
	}								\
      }									\
      if (!is_okay){							\
	print_error(_("argument --%s is not valid under action: %s"),	\
		    (char *) long_options[i].name,			\
		    (char *) actions[action_num]);			\
      }									\
    }									\
  }									\
  break;



void frontend_check_invalid_param(int action_num) {
  switch (action_num){
  case NMOBJ_action_open:{
    check_action({CHECK_ALLOWED_OPEN,
	NMOBJ_to,
	NMOBJ_target_readonly,
	NMOBJ_target_dry_run,
	NMOBJ_target_allow_discards,
	NMOBJ_target_no_read_workqueue,
	NMOBJ_target_no_write_workqueue,
	NMOBJ_is_nokeyring,
	NMOBJ_is_no_map_partition,
	NMOBJ_windhamtab_location,
	NMOBJ_windhamtab_pass,
	CHECK_COMMON})
      }
  case NMOBJ_action_close:{
    check_action({NMOBJ_is_deffered_remove,
	CHECK_COMMON})
      }
  case NMOBJ_action_new:{
    check_action({      NMOBJ_key,
	NMOBJ_key_file,
	NMOBJ_key_stdin,
	NMOBJ_target_mem,
	NMOBJ_target_time,
	NMOBJ_target_level,
	NMOBJ_encrypt_type,
	NMOBJ_block_size,
	NMOBJ_is_no_detect_entropy,
	NMOBJ_decoy_size,
	NMOBJ_is_anonymous_key,
	CHECK_COMMON})
      }
  case NMOBJ_action_addkey:{
    check_action({      CHECK_ALLOWED_OPEN,
	NMOBJ_gen_randkey,
	NMOBJ_target_mem,
	NMOBJ_target_time,
	NMOBJ_target_level,
	NMOBJ_is_no_detect_entropy,
	NMOBJ_is_rapid_add,
	NMOBJ_is_anonymous_key,CHECK_COMMON})
      }
  case NMOBJ_action_delkey:{
    check_action({CHECK_ALLOWED_OPEN,
	NMOBJ_is_anonymous_key,
	NMOBJ_is_no_fill_random_pattern,
	CHECK_COMMON})
      }
  case NMOBJ_action_backup:{
    check_action({CHECK_ALLOWED_OPEN,
	NMOBJ_to,
	CHECK_COMMON})
      }
  case NMOBJ_action_restore:{
    check_action({NMOBJ_to,
	CHECK_COMMON})
      }
  case NMOBJ_action_suspend:{
    check_action({      CHECK_ALLOWED_OPEN,
	CHECK_COMMON})
      }
  case NMOBJ_action_resume:{
    check_action({      CHECK_ALLOWED_OPEN,
	CHECK_COMMON})
      }
  case NMOBJ_action_destory:{
    check_action({NMOBJ_target_decoy, CHECK_COMMON})
      }
  case NMOBJ_action_bench:{
    check_action({})
      }
  }
}



int frontend_check_actions(const char * input) {
  for (int i = 0; (size_t) i < sizeof(actions) / sizeof(char *); i ++) {
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
}



noreturn void frontend_no_input() {
  printf(
	 _(
	   "Windham (%s) Copyright (C) 2023 2024 2025\n\n"

	   "usage: \"windham <action> <target>\"\n"
	   "For help, type 'windham Help' to view help for all possible actions\n\n"

	   "This program comes with ABSOLUTELY NO WARRANTY; for details type 'Help --license'.\n"
	   "This is free software, and you are welcome to redistribute it under certain conditions;\n"),
	 VERSION);
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


void init_key_obj_and_master_key(Key * key, uint8_t master_key[HASHLEN], char * params[]) {
  if (options[NMOBJ_master_key]) {
    if (master_key_to_byte_array(params[NMOBJ_master_key], master_key) == false) {
      print_error(_("error when parsing master key: invalid length"));
    }
    key->key_or_keyfile_location = NULL;
    key->key_type                = NMOBJ_key_file_type_masterkey;
    return;
  }
  memset(master_key, 0, HASHLEN);
  if (options[NMOBJ_key] == 1) {
    key->key_or_keyfile_location = params[NMOBJ_key];
    key->key_type                = NMOBJ_key_file_type_key;
  } else if (options[NMOBJ_key_file] == 1) {
    key->key_or_keyfile_location = params[NMOBJ_key_file];
    key->key_type                = NMOBJ_key_file_type_file;
  } else if (options[NMOBJ_is_systemd] == 1) {
    key->key_or_keyfile_location = NULL;
    key->key_type                = NMOBJ_key_file_type_input_systemd;
  } else if (options[NMOBJ_key_stdin] == 1) {
    key->key_or_keyfile_location = NULL;
    key->key_type                = NMOBJ_key_file_type_input_stdin;
  } else {
    key->key_or_keyfile_location = NULL;
    key->key_type                = NMOBJ_key_file_type_input;
  }
}


void frontend_check_validity_and_execute(int action_num, const char * device, char * params[]) {
  uint8_t   master_key[HASHLEN];
  uintmax_t windhamtab_pass     = 0;
  uintmax_t target_mem          = SIZE_MAX;
  uintmax_t max_unlock_mem      = SIZE_MAX;
  double    target_time         = DEFAULT_TARGET_TIME;
  double    max_unlock_time     = DEFAULT_TARGET_TIME * MAX_UNLOCK_TIME_FACTOR;
  uintmax_t target_level        = KEY_SLOT_EXP_MAX;
  uintmax_t max_unlock_level    = KEY_SLOT_EXP_MAX;
  uintmax_t timeout             = 0;
  uintmax_t block_size          = DEFAULT_BLOCK_SIZE;
  uintmax_t decoy_size          = 0;
  char *    windhamtab_location = NULL;
  char *    encrypt_type        = DEFAULT_DISK_ENC_MODE;


  frontend_check_invalid_param(action_num);
  // redirect the stdout to stderr for NMOBJ_gen_randkey
  if (options[NMOBJ_gen_randkey] == 1) {
    fflush(stdout);
    stdout_fd = dup(STDOUT_FILENO);
    dup2(STDERR_FILENO, STDOUT_FILENO);
  }

  char * end;

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
    max_unlock_level = strtoumax(params[NMOBJ_max_unlock_level], &end, 10);
    if (*end != '\0' || max_unlock_level == 0) {
      print_error(_("bad input for argument %s: not an positive non-zero integer"), "--max-unlock-level");
    }
  }
  if (options[NMOBJ_unlock_timeout] == 1) {
    timeout = strtoumax(params[NMOBJ_unlock_timeout], &end, 10);
    if (*end != '\0') {
      print_error(_("bad input for argument %s: not an positive integer"), "--timeout");
    }
  }
  if (options[NMOBJ_windhamtab_pass] == 1) {
    windhamtab_pass = strtoumax(params[NMOBJ_windhamtab_pass], &end, 10);
    if (*end != '\0') {
      print_error(_("bad input for argument %s: not an positive integer"), "--windhamtab-pass");
    }
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

  if (! options[NMOBJ_is_noadmin]) {
    is_running_as_root();
  }

  if (options[NMOBJ_windhamtab_location]) {
    windhamtab_location = params[NMOBJ_windhamtab_location];
  }

  if (options[NMOBJ_encrypt_type]) {
    encrypt_type = params[NMOBJ_encrypt_type];
  }

  // Done parsing the arguments.

#ifdef IS_FRONTEND_ENTRY
  is_skip_conformation = options[NMOBJ_yes];
  init();
#else
  is_skip_conformation = 1;
#endif

#ifndef CONFIG_USE_SWAP
  if (options[NMOBJ_is_allow_swap]) {
    print_error(_("--allow-swap is disabled from the compile option. Recompile Windham to enable this feature."));
  }
#endif

  // Check invalid arguments

#define $ent(_action_num, _warn_or_err, _msg, _options) if ((action_num == -1 || action_num == (NMOBJ_action_##_action_num)) && !(_options)) { \
    if (strcmp(#_warn_or_err, "warn") == 0) {				\
      print_warning(_(_msg));						\
    } else if (strcmp(#_warn_or_err, "err") == 0) {			\
      print_error(_(_msg));						\
    }									\
  }

#define $is(_x) (options[_x] == 1)
#define $isval(_x, _options) (if ($is(_x) && (params[_x] _options)))
#define $has(_cnt, ...) (_sum_values(__VA_ARGS__, NMOBJ_target_SIZE) <= _cnt)

#include <valid_args.h>


#undef $ent
#undef $is
#undef $has


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
		 BOOL_DEL_START,
		 options[NMOBJ_target_dry_run],
		 options[NMOBJ_target_readonly],
		 options[NMOBJ_target_allow_discards],
		 options[NMOBJ_target_no_read_workqueue],
		 options[NMOBJ_target_no_write_workqueue],
		 options[NMOBJ_is_no_map_partition],
		 options[NMOBJ_is_nokeyring],
		 options[NMOBJ_is_nofail],
		 options[NMOBJ_windhamtab_pass],
		 BOOL_DEL_END);

    break;
  case NMOBJ_action_close:
    // do not init device, since the device is mapper's name.
    action_close(device, options[NMOBJ_is_deffered_remove]);
    // loop frees inside it
    break;
  case NMOBJ_action_new:
    init_device(device, false, false, options[NMOBJ_is_nofail], true);
    action_create(
		  STR_device->name,
		  encrypt_type,
		  key,
		  target_mem,
		  target_time,
		  target_level,
		  block_size,
		  decoy_size,
		  options[NMOBJ_is_no_detect_entropy],
		  options[NMOBJ_is_anonymous_key],
		  options[NMOBJ_is_allow_swap]);
    break;
  case NMOBJ_action_addkey:
    init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy]);

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
		  options[NMOBJ_is_anonymous_key]);
    break;
  case NMOBJ_action_delkey:
    init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy]);

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
    // TODO:
    break;
  case NMOBJ_action_backup:
    init_device(device, false, true, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy]);

    action_backup(
		  STR_device->name,
		  params[NMOBJ_to],
		  options[NMOBJ_target_decoy]);
    break;
  case NMOBJ_action_restore:
    init_device(device, false, true, options[NMOBJ_is_nofail], true);

    action_restore(STR_device->name, params[NMOBJ_to], options[NMOBJ_target_decoy]);
    break;
  case NMOBJ_action_suspend:
    init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy]);

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
    init_device(device, false, false, options[NMOBJ_is_nofail], options[NMOBJ_target_decoy]);
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
    init_device(device, false, false, options[NMOBJ_is_nofail], true);
    action_destory(STR_device->name, options[NMOBJ_target_decoy]);
    break;
  default:
    break;
  }
  windham_exit(0);
}

int main_(int argc, char * argv[argc]) {
  STR_device = alloca(sizeof(Device));
  environ    = alloca(sizeof(char *));
  *environ   = NULL;

  STR_device->block_count = 0;
  STR_device->block_size  = 0;
  STR_device->is_loop     = false;


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
    if (action_num == NMOBJ_action_bench) { // benchmark
      benchmark();
    } else {
      print_error(_("<target> not provided. type 'windham Help' to view help"));
    }
  }
  if (argc >= 3) {
    char * params[NMOBJ_target_SIZE] = {NULL};
    if (memcmp(argv[2], "-", 1) == 0) {
      if (strcmp(argv[2], "--help") == 0 || strcmp(argv[2], "-h") == 0) {
	frontend_help(argv[1]);
      }
      print_error(_("arguments should locate after <device>. "));
    }

    int opt;
    int long_index = 0;
    optind         = 3;
    opterr         = 0;

    memset(options, 0, sizeof(options)); // under testing, options needs to be cleared.
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
  }
  return 0;
}
