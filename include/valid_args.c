/*
 * valid_args.c — argument validation DSL.
 *
 * Included ONCE inside frontend_check_validity_and_execute().
 * The caller must have defined these macros before #include:
 *
 *   need_dev(_action)            — device-required check
 *   opt_allow(_action, ...)      — per-action option allow-list
 *   ent(_action, warn|err, msg, condition) — cross-cutting rules
 *   is(_x)                       — options[_x] == 1
 *   has(_cnt, ...)               — at most _cnt of the listed options set
 */

// ===================================================================
// Section 1 — Device requirements
// ===================================================================
// 需要 <target> 的 action 列表。
// probe / close (--all) / list / bench / help 不需要。

need_dev(open)
need_dev(new)
need_dev(addkey)
need_dev(delkey)
need_dev(backup)
need_dev(restore)
need_dev(suspend)
need_dev(resume)
need_dev(destory)
need_dev(aux)

// Close requires a device unless --all is given.
need_dev_if(close, !is(NMOBJ_close_all))


// ===================================================================
// Section 2 — Per-action option allow-list
// ===================================================================
// 未在 allow-list 中出现的选项会被拒绝：
//   "argument --<name> is not valid under action: <action>"

opt_allow(open,
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

opt_allow(close,
  NMOBJ_is_deffered_remove,
  NMOBJ_close_all,
  ALLOW_COMMON)

opt_allow(new,
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
  NMOBJ_create_exfat,
  ALLOW_COMMON)

opt_allow(addkey,
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

opt_allow(delkey,
  ALLOW_OPEN_COMMON,
  NMOBJ_is_anonymous_key,
  NMOBJ_is_no_fill_random_pattern,
  ALLOW_COMMON)

opt_allow(backup,
  ALLOW_OPEN_COMMON,
  NMOBJ_to,
  ALLOW_COMMON)

opt_allow(restore,
  NMOBJ_to,
  ALLOW_COMMON)

opt_allow(suspend,
  ALLOW_OPEN_COMMON,
  ALLOW_COMMON)

opt_allow(resume,
  ALLOW_OPEN_COMMON,
  ALLOW_COMMON)

opt_allow(destory,
  NMOBJ_target_decoy,
  ALLOW_COMMON)

opt_allow(bench,
  ALLOW_COMMON)

opt_allow(aux,
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

opt_allow(probe,
  NMOBJ_probe_dir,
  NMOBJ_probe_linux,
  NMOBJ_probe_pattern,
  ALLOW_COMMON)

opt_allow(list,
  ALLOW_COMMON)

// help 在 main_() 中提前拦截 frontend_help()，不经过这里。


// ===================================================================
// Section 3 — Cross-cutting rules
// ===================================================================
// ent(_action, err|warn, _("message"), condition)
// 跨 action 的互斥 / 条件 / windhamtab 约束。

ent(ALL, err,
"argument --key, --key-file, --keystdin and --master-key are mutually exclusive.",
has(1, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin))

ent(ALL, err,
"You cannot specify a time or memory limit when setting an iteration level, as the priority of the iteration level"
"is higher than other limits.",
(is(NMOBJ_target_level) && has(0, NMOBJ_target_time, NMOBJ_target_mem)) ||
(is(NMOBJ_max_unlock_level) && has(0, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time)))

ent(open, err,
"--to and --dry-run are mutually exclusive under action \"Open\".",
has(1, NMOBJ_to, NMOBJ_target_dry_run))

ent(open, err,
"Cannot set a read only target's write workqueue status.",
has(1, NMOBJ_target_no_write_workqueue, NMOBJ_target_readonly))

ent(open, err,
"--windhamtab-location is only valid when reading windhamtab file.",
     strcmp("TAB", device) == 0 || !is(NMOBJ_windhamtab_location))

ent(open, err,
"--windhamtab-pass is only valid when reading windhamtab file.",
strcmp("TAB", device) == 0 || !is(NMOBJ_windhamtab_pass))

ent(open, err,
"--dry-run is only valid when using device as target.",
     !(strcmp("TAB", device) == 0 && is(NMOBJ_target_dry_run)))

ent(open, err,
"--to is only valid when using device as target.",
     !(strcmp("TAB", device) == 0 && is(NMOBJ_to)))

ent(open, warn,
"Designate unlock iteration limit using command line arguments will affect on all entities in the windhamtab file.",
     !(strcmp("TAB", device) == 0 &&
      !has(0, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_max_unlock_level)))

ent(open, warn,
"All entities in the windhamtab file will be unlocked using the same given password, this is not what you might want.",
     !(strcmp("TAB", device) == 0 && !is(NMOBJ_windhamtab_pass) &&
      !has(0, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin)))

ent(new, err,
"Systemd password dialog option is only valid when prompting password interactively, however, password is already "
"provided in the commandline.",
     !(is(NMOBJ_is_systemd) && !has(0, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin)))
