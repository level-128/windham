# Quick Start Guide

## 1. Locate your device

Use `lsblk` or `fdisk -l` to find the block device. Examples: `/dev/sdb`, `/dev/nvme0n1p3`.
**The device will be overwritten.**

To locate **existing** Windham partitions, use `Probe`:

```bash
sudo windham Probe              # scan all block devices
```

Each detected partition shows its UUID, encryption type, sector range, block size,
and mount status.

## 2. Create a Windham partition

```bash
sudo windham New /dev/sdb
```

This creates the header and enrolls one passphrase. The default encryption is
`aes-xts-plain64` with 4096-byte sectors, which works for most scenarios.

## 3. Open and map

```bash
sudo windham Open /dev/sdb
# Mapped at /dev/mapper/windham-<uuid>

# Or specify a custom name:
sudo windham Open /dev/sdb --to=mycrypt
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
sudo windham Open /dev/sdb --dry-run
# Prints the master key — back this up securely!
```

**The master key can unlock, control, and modify the entire partition. It cannot
be regenerated if lost or compromised.** Store it offline, on paper, or in a
hardware security module.

---

## List devices

List all active Windham devices:

```bash
sudo windham List
```

---

## Managing passphrases

### Add a new passphrase

```bash
sudo windham AddKey /dev/sdb
# enter new passphrase when prompted
```

By default, this performs a full header re-transform (secure but slow with many
passphrases). Use `--rapid-add` for speed if the slot history attack does not
apply to your threat model.

### Remove a passphrase

```bash
sudo windham DelKey /dev/sdb
```

### List registered passphrases

```bash
sudo windham Open /dev/sdb --dry-run
# Shows key slot status for all 16 slots
```

---

## Suspend / Resume

Suspend stores the intermediate key in the header, allowing passwordless unlock:

```bash
sudo windham Suspend /dev/sdb
# Device can now be opened without a password

# ......

sudo windham Resume /dev/sdb 
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
