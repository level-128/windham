$ent(ALL, err,
"argument --key, --key-file, --keystdin and --master-key are mutually exclusive.",
$has(1, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin))

$ent(ALL, err,
"You cannot specify a time or memory limit when setting an iteration level, as the priority of the iteration level"
"is higher than other limits.",
($is(NMOBJ_target_level) && $has(0, NMOBJ_target_time, NMOBJ_target_mem)) ||
($is(NMOBJ_max_unlock_level) && $has(0, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time)))

$ent(open, err,
"--to and --dry-run are mutually exclusive under action \"Open\".",
$has(1, NMOBJ_to, NMOBJ_target_dry_run))

$ent(open, err,
"Cannot set a read only target's write workqueue status.",
$has(1, NMOBJ_target_no_write_workqueue, NMOBJ_target_readonly))

$ent(open, err,
"--windhamtab-location is only valid when reading windhamtab file.",
     strcmp("TAB", device) == 0 || !$is(NMOBJ_windhamtab_location))

$ent(open, err,
"--windhamtab-pass is only valid when reading windhamtab file.",
strcmp("TAB", device) == 0 || !$is(NMOBJ_windhamtab_pass))

$ent(open, err,
"--dry-run is only valid when using device as target.",
     !(strcmp("TAB", device) == 0 && $is(NMOBJ_target_dry_run)))

$ent(open, err,
"--to is only valid when using device as target.",
     !(strcmp("TAB", device) == 0 && $is(NMOBJ_to)))

$ent(open, warn,
"Designate unlock iteration limit using command line arguments will affect on all entities in the windhamtab file.",
     !(strcmp("TAB", device) == 0 &&
      !$has(0, NMOBJ_max_unlock_mem, NMOBJ_max_unlock_time, NMOBJ_max_unlock_level)))

$ent(open, warn,
"All entities in the windhamtab file will be unlocked using the same given password, this is not what you might want.",
     !(strcmp("TAB", device) == 0 && !$is(NMOBJ_windhamtab_pass) &&
      !$has(0, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin)))

$ent(new, err,
"Systemd password dialog option is only valid when prompting password interactively, however, password is already "
"provided in the commandline.",
     !($is(NMOBJ_is_systemd) && !$has(0, NMOBJ_key, NMOBJ_key_file, NMOBJ_master_key, NMOBJ_key_stdin)))

