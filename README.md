# Windham

Windham is libre software for disk encryption, an implementation of its own specification, built on the
Linux kernel's dm-crypt module. It combines the functionality of LUKS with plausible deniability and
hidden volume features akin to VeraCrypt, while unlocking in constant time regardless of how many
passphrases are registered.

[中文](/docs/zh-cn/README.md)

> **Pre-release software.** On-disk format is stable but not yet frozen. Back up your master key.

---

## Features at a glance

- **Transparent block-level encryption** via dm-crypt (aes-xts-plain64 by default)
- **Plausible deniability** — cryptographically random on-disk format with no signatures,
  no magic numbers, and optional Decoy Partition (steganography)
- **16 passphrase slots** — supports password, key file, master key. Unlock time is
  independent of slot count
- **LINK_OPEN cascade** — open one device and all linked partitions unlock automatically
  in a configurable priority tree. Supports `SHORTCUT` flag to prune sibling branches,
  enabling fault-tolerant RAID setups with surviving path discovery
- **Auxiliary data zone** — per-key encrypted metadata: plaintext notes, shell commands
  executed on open, and LINK_OPEN entries. Survives header re-transforms
- **Probe** — scan block devices or files for Windham partitions (shebang / magic /
  suspend / entropy). Displays device attributes, UUID, mount info
- **Unicode password input** — Tab+Space to enter hex code points; passwords normalized
  to UTF-32BE before hashing for cross-platform key derivation
- **Tamper resistance** — header modifications while suspended are detected; multiple
  built-in integrity markers validate every open
- **Self-correlated metadata** — header re-transform changes most bits to obscure
  modification history (defeats slot-history attack)

---

## 10-second quick start

```bash
# Build
git clone https://github.com/level-128/windham.git --depth=1 && cd windham
cmake -B build && cmake --build build

# Create, open, use, close
sudo windham New   /dev/sdb                       # create encrypted device
sudo windham Open  /dev/sdb                       # unlock → /dev/mapper/windham-<uuid>
sudo mkfs.ext4     /dev/mapper/windham-*          # format
sudo mount         /dev/mapper/windham-* /mnt     # use
sudo windham Close windham-*                      # lock
sudo windham List                                 # list active mappings
```

---

## Documentation

| Document | Content |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | Step-by-step guide (New, Open, Close, Suspend, AddKey, DelKey) |
| [docs/install.md](docs/install.md) | Build dependencies, cross-compilation, feature switches, ISO C mode |
| [docs/security.md](docs/security.md) | Master key hierarchy, slot history attack, anonymous keys, side channels, tamper resistance |
| [docs/aux.md](docs/aux.md) | Aux zone types (PLAINTEXT, SHELL, LINK_OPEN), flags, RAID cascade setup |
| [docs/decoy.md](docs/decoy.md) | Decoy partition guide — GPT layout, TRIM issues, filesystem recommendations |
| [docs/windhamtab.md](docs/windhamtab.md) | /etc/windhamtab, Clevis + TPM2 integration, systemd init |
| [docs/pid1.md](docs/pid1.md) | Running Windham as PID 1 (embedded / early userspace) |
| [docs/contribute.md](docs/contribute.md) | Developer setup, test suite, code structure |
| [scripts/windham-raid-setup.sh](scripts/windham-raid-setup.sh) | One-shot RAID cascade script (N disks, redundant SHORTCUT links) |

For per-action option reference: `windham Help <action>` (e.g. `windham Help Open`).

---

## Supported platforms

| Tier | Requirements | Capabilities |
|---|---|---|
| **Full** (GNU/Linux) | Linux 2.6+, libdevmapper, libblkid, gettext, C11 compiler with GNU extensions | Everything |
| **Basic** (ISO C11) | `stdlib.h`, `string.h`, `stdio.h`, `threads.h` (optional), ~510 KB heap | Header management, unlock, probe (no dm-crypt mapping) |

Full-support dependencies: `libdevmapper-dev`, `linux-headers`, `libgettextpo-dev`, `libblkid-dev`, `libkeyutils-dev`.

---

## License

GPL-3.0-or-later. Copyright (C) 2023–2026 level-128.  
Third-party library licenses: [library/license.md](library/license.md).
