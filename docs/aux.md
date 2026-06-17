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
  (no encryption). These entries are visible during `--probe` even without a valid key.
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

A shell command executed when the device is opened. Added via `--add-command=<cmd>`.

**Struct**: `AuxContentShell` — type marker, flags, timeout (seconds), command length,
command string (char32_t).

**Flags**:
- `BLCKOPEN` (value 1) — block the Open operation if the command fails. This is the
  default flag behavior for `--add-command`.

```bash
# Assemble RAID after unlock; block open if assembly fails
windham Aux /dev/sda --key=mypass \
    --add-command="mdadm --assemble /dev/md0 /dev/mapper/windham-*" \
    --flag=BLCKOPEN
```

### LINK_OPEN (type 2)

A reference to another Windham partition. When the parent device is opened, the
linked device is automatically unlocked in cascade. Added via `--add-link=<path>`.

**Struct**: `AuxContentLinkOpen` — type marker, flags, target unlock level, priority,
target UUID, pre-hashed char32_t password.

**Flags**:
- `SHORTCUT` (value 4) — if this link opens successfully, skip all remaining sibling
  links at the same cascade depth level.

**Priority**: `--link-prio=<0-255>` (default 128). Lower = processed earlier. Within
a device's aux zone, LINK_OPEN entries are sorted by priority; the lowest-priority
entry opens first.

**Target password**: Use `--target-key=<password>` (non-interactive) or
`--target-keyfile=<path>`. If neither is given, you will be prompted interactively.

```bash
# Link /dev/sdb to /dev/sda; when sda opens, sdb opens automatically
windham Aux /dev/sda --key=mypass \
    --add-link=/dev/sdb --target-key=otherpass --link-prio=100
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
    --add-link=/dev/sdb --target-key=raidpass --link-prio=50 --link-flag=SHORTCUT
sudo windham Aux /dev/sda --key=raidpass \
    --add-link=/dev/sdc --target-key=raidpass --link-prio=100 --link-flag=SHORTCUT

# Disk B → C (prio=50, SHORTCUT), A (prio=100, SHORTCUT)
sudo windham Aux /dev/sdb --key=raidpass \
    --add-link=/dev/sdc --target-key=raidpass --link-prio=50 --link-flag=SHORTCUT
sudo windham Aux /dev/sdb --key=raidpass \
    --add-link=/dev/sda --target-key=raidpass --link-prio=100 --link-flag=SHORTCUT

# Disk C → A (prio=50, SHORTCUT), B (prio=100, SHORTCUT)
sudo windham Aux /dev/sdc --key=raidpass \
    --add-link=/dev/sda --target-key=raidpass --link-prio=50 --link-flag=SHORTCUT
sudo windham Aux /dev/sdc --key=raidpass \
    --add-link=/dev/sdb --target-key=raidpass --link-prio=100 --link-flag=SHORTCUT
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
    --add-link=/dev/home --target-key=homepass --link-prio=50 --link-flag=SHORTCUT
```

### Offline backup chain

Create a chain where unlocking the primary device also unlocks a backup device
at an offsite location (when connected):

```bash
windham Aux /dev/primary --key=main \
    --add-link=/dev/disk/by-uuid/<backup-uuid> --target-key=backupkey --link-prio=200
```

## Aux zone management

| Command | Description |
|---|---|
| `--add=<text>` | Add a PLAINTEXT entry |
| `--add-command=<cmd> --flag=<flag>` | Add a SHELL entry |
| `--add-link=<path> --target-key=...` | Add a LINK_OPEN entry |
| `--del` | Delete all entries matching the current key |
| `--probe` | List entries matching the current key + all public entries |

All commands require unlocking the aux zone first — use `--key`, `--key-file`, or
`--keystdin`.

### Listing aux entries

```bash
# Show all entries (encrypted for current key + public entries)
windham Aux /dev/sda --key=mypass --probe

# When unlocked with master key, only public entries are shown
windham Aux /dev/sda --master-key=<hex> --probe
```

### Deleting all aux entries for a key

```bash
windham Aux /dev/sda --key=mypass --del
# Removes ALL aux entries that were encrypted with this key's inited_key
```
