# Auxiliary Data Zone

Every Windham partition has an optional **auxiliary data zone** — a small (default 8 KiB)
region immediately after the header where per-key metadata is stored. Each aux entry
is independently encrypted with a key derived from the keyslot used to unlock the device.

## Design

- **Location**: `start_aux_sector` sectors after device start (default: header area end, sector 40)
- **Size**: configurable via `--aux-sector-size` (default: 16 sectors = 8 KiB)
- **Encryption**: Each entry has its own random IV and is AES-CBC encrypted. The key
  is derived from the unlocking keyslot's `inited_key`.
- **Public entries**: If unlocked with `--master-key`, the aux slot key is all-zero
  (no encryption). These entries are visible during `--aux-probe` even without a valid key.
- **Cross-re-transform persistence**: The aux zone is re-encrypted with the new
  `master_key_mask` (CBC IV) during normal (non-rapid) header re-transform, so aux
  data survives header changes.
- **Automatic cleanup**: When a key is deleted (`DelKey`), aux entries encrypted with
  that key are automatically removed.

## Aux entry types

### PLAINTEXT (type 0)

Raw `char32_t` content stored directly. Added via `--add=<content>`.

```bash
windham Aux /dev/sda --key=mypass --add="Backup passphrase hint: blue elephant"
```

### SHELL (type 1)

A shell command executed when the device is opened. Added via `--aux-add-command=<cmd>`.

**Struct**: `AuxContentShell` — type marker, flags, timeout (seconds), command length,
command string (char32_t).

**Flags**:
- `BLCKOPEN` (value 1) — block the Open operation if the command fails. This is the
  default flag behavior for `--aux-add-command`.

```bash
# Assemble RAID after unlock; block open if assembly fails
windham Aux /dev/sda --key=mypass \
    --aux-add-command="mdadm --assemble /dev/md0 /dev/mapper/windham-*" \
    --aux-flag=BLCKOPEN
```

### LINK_OPEN (type 2)

A reference to another Windham partition. When the parent device is opened, the
linked device is automatically unlocked in cascade. Added via `--aux-add-link=<path>`.

**Struct**: `AuxContentLinkOpen` — type marker, flags, target unlock level, priority,
target UUID, pre-hashed char32_t password.

**Flags**:
- `SHORTCUT` (value 4) — if this link opens successfully, skip all remaining sibling
  links at the same cascade depth level.

**Priority**: `--aux-link-prio=<0-255>` (default 128). Lower = processed earlier. Within
a device's aux zone, LINK_OPEN entries are sorted by priority; the lowest-priority
entry opens first.

**Target password**: Use `--aux-target-key=<password>` (non-interactive) or
`--aux-target-keyfile=<path>`. If neither is given, you will be prompted interactively.

```bash
# Link /dev/sdb to /dev/sda; when sda opens, sdb opens automatically
windham Aux /dev/sda --key=mypass \
    --aux-add-link=/dev/sdb --aux-target-key=otherpass --aux-link-prio=100
```

#### Cascade behavior

When `Open` is invoked on a device with LINK_OPEN entries:

1. The parent device is unlocked and mapped.
2. Its aux zone is read, decrypted, and probed for LINK_OPEN entries.
3. Each entry is sorted by `prio` (descending), then pushed to a FIFO queue at
   `depth = parent_depth + 1`.
4. The FIFO processes linked devices one-by-one, each potentially adding their
   _own_ LINK_OPEN entries at higher depths (recursive cascade).
5. If a link has the `SHORTCUT` flag and opens successfully, all remaining entries
   at the same depth are discarded (pruning the cascade tree).
6. Devices already opened (matched by UUID) are skipped — no loops.
7. UUID-to-device resolution can be restricted with `--aux-link=/dev/sdX,/dev/sdY`
   (avoids scanning `/proc/partitions`).

```
Example topology:
  A → B(prio=50, SHORTCUT), C(prio=100)
  B → D, E

  Open A:
    1. A's links sorted: [C(100), B(50)]
    2. B opens first → SHORTCUT → C pruned
    3. D, E open
  Result: A, B, D, E opened; C skipped
```

## Real-world scenarios

### RAID 5/6 setup

For RAID arrays that must survive disk failures during unlock, give each disk
**redundant** LINK_OPEN entries to all other disks with `SHORTCUT`. When a link
succeeds, remaining siblings at the same depth are pruned; when a link fails
(disk missing), the next priority link takes over.

**3-disk RAID 5** (tolerates 1 failure): each disk links to the other two, with
the lower-prio link processed first and `SHORTCUT` on all links:

```bash
# Step 1: Create Windham on each disk
for dev in /dev/sda /dev/sdb /dev/sdc; do
    sudo windham New $dev --key=raidpass
done

# Step 2: Redundant links on every disk
# Disk A → B (prio=50, SHORTCUT), C (prio=100, SHORTCUT)
sudo windham Aux /dev/sda --key=raidpass \
    --aux-add-link=/dev/sdb --aux-target-key=raidpass --aux-link-prio=50 --aux-link-flag=SHORTCUT
sudo windham Aux /dev/sda --key=raidpass \
    --aux-add-link=/dev/sdc --aux-target-key=raidpass --aux-link-prio=100 --aux-link-flag=SHORTCUT

# Disk B → C (prio=50, SHORTCUT), A (prio=100, SHORTCUT)
sudo windham Aux /dev/sdb --key=raidpass \
    --aux-add-link=/dev/sdc --aux-target-key=raidpass --aux-link-prio=50 --aux-link-flag=SHORTCUT
sudo windham Aux /dev/sdb --key=raidpass \
    --aux-add-link=/dev/sda --aux-target-key=raidpass --aux-link-prio=100 --aux-link-flag=SHORTCUT

# Disk C → A (prio=50, SHORTCUT), B (prio=100, SHORTCUT)
sudo windham Aux /dev/sdc --key=raidpass \
    --aux-add-link=/dev/sda --aux-target-key=raidpass --aux-link-prio=50 --aux-link-flag=SHORTCUT
sudo windham Aux /dev/sdc --key=raidpass \
    --aux-add-link=/dev/sdb --aux-target-key=raidpass --aux-link-prio=100 --aux-link-flag=SHORTCUT
```

**How fault tolerance works** — opening disk A:

| Disk A link | B present? | C present? | Cascade result |
|---|---|---|---|
| B(50,SHORTCUT) then C(100,SHORTCUT) | ✓ | ✓ | B opens → SHORTCUT prunes C. All 3 open. |
| B(50,SHORTCUT) then C(100,SHORTCUT) | ✗ | ✓ | B fails. C opens → SHORTCUT fires (no siblings left). A + C open. |
| B(50,SHORTCUT) then C(100,SHORTCUT) | ✓ | ✗ | B opens → SHORTCUT prunes C. B→A skipped (A already open). A + B open. |

For **RAID 6** (5+ disks, tolerates 2 failures), give each disk 4 links (one to
each sibling) with SHORTCUT. The cascade will find a path through any surviving
disks.

After all surviving disks are mapped, assemble the RAID separately:

```bash
sudo windham Open /dev/sda --key=raidpass
sudo mdadm --assemble /dev/md0 /dev/mapper/windham-*
```

For boot-time automation, use `windhamtab` with one pass for the cascade unlock
and a second pass for `mdadm` assembly.

### Root partition cascade

Link your home partition to your root partition so a single unlock cascades:

```bash
# Link encrypted /home to encrypted /root
windham Aux /dev/root --key=rootpass \
    --aux-add-link=/dev/home --aux-target-key=homepass --aux-link-prio=50 --aux-link-flag=SHORTCUT
```

### Offline backup chain

Create a chain where unlocking the primary device also unlocks a backup device
at an offsite location (when connected):

```bash
windham Aux /dev/primary --key=main \
    --aux-add-link=/dev/disk/by-uuid/<backup-uuid> --aux-target-key=backupkey --aux-link-prio=200
```

### Automated RAID setup script

`scripts/windham-raid-setup.sh` automates the entire RAID cascade setup:

```bash
# RAID6: 4 disks, each links to 3 others (tolerates 2 failures)
sudo ./scripts/windham-raid-setup.sh --raid=raid6 --pass=raidpass /dev/sd{b,c,d,e}

# RAID5: 5 disks, links to 2 others (tolerates 1 failure)
sudo ./scripts/windham-raid-setup.sh --raid=raid5 /dev/sd{a,b,c,d,e}

# Full redundancy: every disk links to every other
sudo ./scripts/windham-raid-setup.sh --pass=mypass /dev/sd{a,b,c}
```

The script handles:
1. Shared cascade key generation
2. Partition creation + user passphrase enrollment
3. Redundant LINK_OPEN entries with SHORTCUT
4. SHELL command (`mdadm --assemble /dev/md0 @`) on every disk with BLCKOPEN
5. Public "RAID member" warning labels on each disk

After setup, opening the first disk cascades and assembles automatically:

```bash
sudo windham Open /dev/sdb
# All disks unlock → SHELL runs → /dev/md0 ready
```

| Script Option | Values | Description |
|---|---|---|
| `--raid=` | `all` (default), `raid5`, `raid6` | Link topology |
| `--pass=` | string | User password (prompts if omitted) |
| `--open-first=` | device path | Cascade trigger disk (default: first arg) |
| `--dry-run` | — | Print commands without executing |

## Aux zone management

| Command | Description |
|---|---|
| `--aux-add=<text>` | Add a PLAINTEXT entry |
| `--aux-add-command=<cmd> --aux-flag=<flag>` | Add a SHELL entry |
| `--aux-add-link=<path> --aux-target-key=...` | Add a LINK_OPEN entry |
| `--aux-del` | Delete all entries matching the current key |
| `--aux-probe` | List entries matching the current key + all public entries |

All commands require unlocking the aux zone first — use `--key`, `--key-file`, or
`--keystdin`.

### Listing aux entries

```bash
# Show all entries (encrypted for current key + public entries)
windham Aux /dev/sda --key=mypass --aux-probe

# When unlocked with master key, only public entries are shown
windham Aux /dev/sda --master-key=<hex> --aux-probe
```

### Deleting all aux entries for a key

```bash
windham Aux /dev/sda --key=mypass --aux-del
# Removes ALL aux entries that were encrypted with this key's inited_key
```
