# Quick Start Guide

## 1. Locate your device

Use `lsblk` or `fdisk -l` to find the block device. Examples: `/dev/sdb`, `/dev/nvme0n1p3`.
**The device will be overwritten.**

## 2. Create a Windham partition

```bash
sudo windham New /dev/sdb --key="your passphrase here"
```

This creates the header and enrolls one passphrase. The default encryption is
`aes-xts-plain64` with 4096-byte sectors.

Options that affect KDF strength (relevant for weak passphrases):
- `--target-time=<sec>` — KDF computation time (default 1.5s, higher = more secure)
- `--target-memory=<KiB>` — max memory for KDF
- `--target-level=<n>` — max KDF iteration level

## 3. Open and map

```bash
sudo windham Open /dev/sdb --key="your passphrase here"
# Mapped at /dev/mapper/windham-<uuid>

# Or specify a custom name:
sudo windham Open /dev/sdb --key="your passphrase here" --to=mycrypt
# Mapped at /dev/mapper/mycrypt
```

## 4. Create a filesystem

```bash
sudo mkfs.ext4 /dev/mapper/mycrypt
```

## 5. Mount and use

```bash
sudo mount /dev/mapper/mycrypt /mnt
# ... use the filesystem ...
sudo umount /mnt
```

## 6. Close (lock)

```bash
sudo windham Close mycrypt
```

## 7. Back up your master key

```bash
sudo windham Open /dev/sdb --key="your passphrase here" --dry-run
# Prints the master key — back this up securely!
```

**The master key can unlock, control, and modify the entire partition. It cannot
be regenerated if lost or compromised.** Store it offline, on paper, or in a
hardware security module.

---

## Managing passphrases

### Add a new passphrase

```bash
sudo windham AddKey /dev/sdb --key="old passphrase" --target-time=2
# Enter new passphrase when prompted
```

By default, this performs a full header re-transform (secure but slow with many
passphrases). Use `--rapid-add` for speed if the slot history attack does not
apply to your threat model.

### Remove a passphrase

```bash
sudo windham DelKey /dev/sdb --key="passphrase to remove"
```

### List registered passphrases

```bash
sudo windham Open /dev/sdb --key="any valid passphrase" --dry-run
# Shows key slot status for all 16 slots
```

---

## Suspend / Resume

Suspend stores the intermediate key in the header, allowing passwordless unlock:

```bash
sudo windham Suspend /dev/sdb --key="your passphrase"
# Device can now be opened without a password
sudo windham Open /dev/sdb
# ...
sudo windham Close windham-*
sudo windham Resume /dev/sdb --key="your passphrase"
# Device requires password again
```

---

## Probe — find Windham devices

```bash
# Scan all block devices
sudo windham Probe

# Probe a specific device
sudo windham Probe --dir=/dev/sdb

# Probe all files in a directory
sudo windham Probe --dir=/mnt/headers/
```

---

## Backup and restore

```bash
sudo windham Backup /dev/sdb --to=windham_backup
sudo windham Restore /dev/sdb --to=windham_backup
```

---

## Next steps

- Run `windham Help <action>` for complete option reference
- Set up [LINK_OPEN cascade](aux.md) for multi-device unlock
- Configure [/etc/windhamtab](windhamtab.md) for boot-time unlock
- Read the [security documentation](security.md)
