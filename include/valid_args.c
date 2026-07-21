/*
 * valid_args.c -- argument validation DSL.
 *
 * Included ONCE inside frontend_check_validity_and_execute().
 * The caller must have defined these macros before #include:
 *
 *   need_dev(_action)            -- device-required check
 *   opt_allow(_action, ...)      -- per-action option allow-list
 *   ent(_action, warn|err, msg, condition) -- cross-cutting rules
 *   is(_x)                       -- options[_x] == 1
 *   has(_cnt, ...)               -- at most _cnt of the listed options set
 */

// ===================================================================
// Section 1 -- Device requirements
// ===================================================================
// Actions that require a <target>.
// probe / close (--all) / list / bench / help do not

need_dev(NMOBJ_action_open)
need_dev(NMOBJ_action_new)
need_dev(NMOBJ_action_addkey)
need_dev(NMOBJ_action_delkey)
need_dev_if(NMOBJ_action_backup, !is(NMOBJ_qrcode))
need_dev(NMOBJ_action_restore)
need_dev(NMOBJ_action_suspend)
need_dev(NMOBJ_action_resume)
need_dev(NMOBJ_action_destory)
need_dev(NMOBJ_action_aux)

// Close requires a device unless --all is given.
need_dev_if(NMOBJ_action_close, !is(NMOBJ_close_all))


// ===================================================================
// Section 2 -- Per-action option allow-list
// ===================================================================
// Options not in the allow-list are rejected:
//   "argument --<name> is not valid under action: <action>"

opt_allow(NMOBJ_action_open,
  ALLOW_OPEN_COMMON,
  NMOBJ_to,
  NMOBJ_target_readonly,
  NMOBJ_target_dry_run,
  NMOBJ_target_allow_discards,
  NMOBJ_target_no_read_workqueue,
  NMOBJ_target_no_write_workqueue,
  NMOBJ_is_nokeyring,
  NMOBJ_is_no_map_partition,
  NMOBJ_is_no_aux,
  NMOBJ_windhamtab_location,
  NMOBJ_windhamtab_pass,
  NMOBJ_aux_link_paths,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_close,
  NMOBJ_is_deffered_remove,
  NMOBJ_close_all,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_new,
  NMOBJ_key,
  NMOBJ_key_file,
  NMOBJ_key_stdin,
  NMOBJ_target_mem,
  NMOBJ_target_time,
  NMOBJ_target_level,
  NMOBJ_encrypt_type,
  NMOBJ_block_size,
  NMOBJ_is_no_detect_entropy,
  NMOBJ_decoy_size,
  NMOBJ_disk_file_size,
  NMOBJ_is_anonymous_key,
  NMOBJ_is_allow_swap,
#ifdef CFG_FF_CREATE
  NMOBJ_create_exfat,
#endif
  ALLOW_COMMON)

opt_allow(NMOBJ_action_addkey,
  ALLOW_OPEN_COMMON,
  NMOBJ_gen_randkey,
  NMOBJ_target_mem,
  NMOBJ_target_time,
  NMOBJ_target_level,
  NMOBJ_is_no_detect_entropy,
  NMOBJ_is_rapid_add,
  NMOBJ_is_anonymous_key,
  NMOBJ_new_key,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_delkey,
  ALLOW_OPEN_COMMON,
  NMOBJ_is_anonymous_key,
  NMOBJ_is_no_fill_random_pattern,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_backup,
  ALLOW_OPEN_COMMON,
  NMOBJ_to,
  NMOBJ_is_fold,
  NMOBJ_qrcode,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_restore,
  ALLOW_OPEN_COMMON,
  NMOBJ_to,
  NMOBJ_is_fold,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_suspend,
  ALLOW_OPEN_COMMON,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_resume,
  ALLOW_OPEN_COMMON,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_destory,
  NMOBJ_target_decoy,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_bench,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_aux,
  ALLOW_OPEN_COMMON,
  NMOBJ_aux_add,
  NMOBJ_aux_type,
  NMOBJ_aux_del,
  NMOBJ_aux_probe,
  NMOBJ_aux_add_command,
  NMOBJ_aux_flag,
  NMOBJ_aux_add_link,
  NMOBJ_aux_rm,
  NMOBJ_target_key,
  NMOBJ_target_key_file,
  NMOBJ_link_flag,
  NMOBJ_link_prio,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_probe,
  NMOBJ_probe_dir,
  NMOBJ_probe_linux,
  NMOBJ_probe_pattern,
  ALLOW_COMMON)

opt_allow(NMOBJ_action_list,
  ALLOW_COMMON)

// help is intercepted early in main_() by frontend_help(), not routed here.


// ===================================================================
// Section 3 -- Cross-cutting rules
// ===================================================================
// ent(_action, err|warn, _("message"), condition)
// Cross-action mutual exclusion / conditions / windhamtab constraints.

ent(NMOBJ_action_ALL, err,
"argument --key, --key-file, --keystdin and --master-key are mutually exclusive.",
has(1, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin))

ent(NMOBJ_action_ALL, err,
"You cannot specify a time or memory limit when setting an iteration level, as the priority of the iteration level"
"is higher than other limits.",
(is(NMOBJ_target_level) && has(0, NMOBJ_target_time, NMOBJ_target_mem)) ||
(is(NMOBJ_max_unlock_level) && has(0, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time)))

ent(NMOBJ_action_open, err,
"--to and --dry-run are mutually exclusive under action \"Open\".",
has(1, NMOBJ_to, NMOBJ_target_dry_run))

ent(NMOBJ_action_open, err,
"Cannot set a read only target's write workqueue status.",
has(1, NMOBJ_target_no_write_workqueue, NMOBJ_target_readonly))

ent(NMOBJ_action_open, err,
"--windhamtab-location is only valid when reading windhamtab file.",
     strcmp("TAB", device) == 0 || !is(NMOBJ_windhamtab_location))

ent(NMOBJ_action_open, err,
"--windhamtab-pass is only valid when reading windhamtab file.",
strcmp("TAB", device) == 0 || !is(NMOBJ_windhamtab_pass))

ent(NMOBJ_action_open, err,
"--dry-run is only valid when using device as target.",
     !(strcmp("TAB", device) == 0 && is(NMOBJ_target_dry_run)))

ent(NMOBJ_action_open, err,
"--to is only valid when using device as target.",
     !(strcmp("TAB", device) == 0 && is(NMOBJ_to)))

ent(NMOBJ_action_open, warn,
"Designate unlock iteration limit using command line arguments will affect on all entities in the windhamtab file.",
     !(strcmp("TAB", device) == 0 &&
      !has(0, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_max_unlock_level)))

ent(NMOBJ_action_open, warn,
"All entities in the windhamtab file will be unlocked using the same given password, this is not what you might want.",
     !(strcmp("TAB", device) == 0 && !is(NMOBJ_windhamtab_pass) &&
      !has(0, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin)))

ent(NMOBJ_action_new, err,
"Systemd password dialog option is only valid when prompting password interactively, however, password is already "
"provided in the commandline.",
     !(is(NMOBJ_is_systemd) && !has(0, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin)))
