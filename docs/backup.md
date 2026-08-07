# Backup & Restore

Every Windham header holds the master key, all 16 passphrase slots, the keypool,
and the aux-zone key. Losing the header means losing the data — back it up.
Windham offers three backup modes and a matching restore path.

## Backup modes

### Full header backup (default)

```bash
sudo windham Backup /dev/sdb --to=windham_backup
```

- Dumps the **raw encrypted header** (~20 KB) including **all** registered
  passphrase slots.
- Requires the device plus a valid key (`--key`, `--key-file`, `--master-key`).
- Refuses to overwrite an existing file — delete it manually if you really want
  to replace a backup.
- Restore with `Restore --to`.

### Fold backup (`--fold`)

```bash
sudo windham Backup --fold --to=sdb_fold.bin /dev/sdb --key=123
```

- Unlocks the device and exports **only the single keyslot** matched by the
  given key: one `Key_slot` (144 B) plus the UUID, salt, and metadata —
  about 960 bytes total.
- All other slots are zeroed and the metadata is re-encrypted with the master
  key, so the file is ciphertext and reveals nothing extra.
- Designed for paper recovery, QR encoding, or storing one key offline without
  exposing the others.
- Restoring requires the same passphrase (or master key) that created the backup.

### QR code backup (`--qrcode`)

```bash
# From a device (live): build fold data in memory, print QR to terminal
sudo windham Backup --qrcode /dev/sdb --key=123

# Save as a 1-bit BMP instead of terminal output
sudo windham Backup --qrcode=sdb_qr.bmp /dev/sdb --key=123

# Offline: encode an existing fold backup — no device needed
sudo windham Backup --qrcode --to=sdb_fold.bin
```

- Encodes the same fold data as a QR code (auto-selected minimum version,
  ECC medium).
- Terminal output uses Unicode block characters — needs a Unicode-capable
  terminal; otherwise use the BMP variant.
- The `--qrcode` without `--to` and without a device has no data source and
  errors out.

## Restore

```bash
# Full header backup
sudo windham Restore /dev/sdb --to=windham_backup

# Fold backup (needs the passphrase / master key used at backup time)
sudo windham Restore --fold /dev/sdb --to=sdb_fold.bin --key=123
```

**Never clone a Windham device.** Restore always preserves the original sector
range recorded in the backup — restoring onto a device of a different size is
refused. Two devices sharing the same header share the same master key, which
is a catastrophic security risk.

## Safety notes

- Store backups offline (paper, QR printout, or disconnected media). A stolen
  backup plus a stolen device means a stolen disk.
- After `Destroy`, also delete your backups — the master key they contain still
  opens the data if the header is ever reconstructed.
- The `--decoy` flag applies to backups of decoy partitions (`Backup --decoy`,
  `Restore --decoy`).
