# Windham

Windham is libre software for disk encryption, an implementation of its own specification, built on the
Linux kernel's dm-crypt module. It combines the functionality of LUKS with plausible deniability and
hidden volume features akin to VeraCrypt, while unlocking in constant time regardless of how many
passphrases are registered.

[中文](/docs/zh-cn/README.md)

> **Pre-release software.** On-disk format is stable but not yet frozen. Back up your master key.

---

## Features at a glance

- **Transparent block-level encryption** — Linux dm-crypt with any filesystem combination
- **Plausible deniability** — cryptographically random on-disk format with no signatures,
  no magic numbers, and optional Decoy Partition (steganography)
- **16 passphrase slots** — supports password, key file, master key. Unlock time is
  independent of slot count
- **LINK_OPEN cascade** — open one device and all linked partitions unlock automatically
  in a configurable priority tree. Supports `SHORTCUT` flag to prune sibling branches,
  enabling fault-tolerant RAID setups with surviving path discovery
- **Auxiliary data zone** — per-key encrypted metadata: plaintext notes, shell commands
  executed after open, and LINK_OPEN entries. Survives header re-transforms
- **Tamper resistance** — any modification to the header is detected; multiple built-in
  integrity markers prevent tampering even while suspended in plaintext
- **Self-correlated metadata** — header re-transform changes most bits to obscure
  modification history (defeats slot-history attack)
- **Variable key derivation** — memory-hard KDF (Argon2id) with runtime-variable
  parameters, significantly mitigating ASIC-based brute-force attacks

---

## 10-second quick start

```bash
# Build
git clone https://github.com/level-128/windham.git --depth=1 && cd windham
cmake -B build && cmake --build build
```

### Supported platforms

| Tier | Requirements | Capabilities |
|---|---|---|
| **Full** (GNU/Linux) | Linux 2.6+, C11 compiler with GNU extensions, `linux-headers` | Everything |
| **Basic** (ISO C11) | `stdlib.h`, `string.h`, `stdio.h`, `threads.h` (optional), ~510 KB heap | Header management, unlock, probe (no dm-crypt mapping) |

Full-support dependencies: `linux-headers`, `libgettextpo-dev` (optional, for i18n).  
`libblkid` and `libkeyutils` are loaded at runtime via `dlopen` — the binary runs without them, with degraded functionality. `libdevmapper` is no longer required. See [install guide](docs/install.md).


```bash
# Create:
sudo windham New   /dev/sdb                        # create encrypted device
# For existing devices:
sudo windham Probe                                 # list Windham partitions

# Unlock:
sudo windham Open  /dev/sdb --to=<name>            # unlock → /dev/mapper/<name>
# Without --to, the name defaults to "windham-<UUID>"
sudo mkfs.ext4     /dev/mapper/windham-*           # format (EXT4 example)
sudo mount         /dev/mapper/windham-* /mnt      # mount and use
```

```bash
sudo windham List                                  # list active mappings

sudo windham Close <name>                          # lock
# or
sudo windham Close --all                           # lock all devices
```

---

## Documentation

| Document | Content |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | Step-by-step guide (New, Open, Close, Suspend, AddKey, DelKey) |
| [docs/install.md](docs/install.md) | Build dependencies, cross-compilation, feature switches, ISO C mode |
| [docs/security.md](docs/security.md) | Master key hierarchy, slot history attack, anonymous keys, side channels, tamper resistance |
| [docs/aux.md](docs/auxzone.md) | Aux zone types (PLAINTEXT, SHELL, LINK_OPEN), flags, RAID cascade setup |
| [docs/decoy.md](docs/decoy.md) | Decoy partition guide — GPT layout, TRIM issues, filesystem recommendations |
| [docs/windhamtab.md](docs/windhamtab.md) | /etc/windhamtab, Clevis + TPM2 integration, systemd init |
| [docs/pid1.md](docs/pid1.md) | Running Windham as PID 1 (embedded / early userspace) |
| [docs/contribute.md](docs/contribute.md) | Developer setup, test suite, code structure |
| [scripts/windham-raid-setup.sh](scripts/windham-raid-setup.sh) | One-shot RAID cascade script (N disks, redundant SHORTCUT links) |

For per-action option reference: `windham Help <action>` (e.g. `windham Help Open`).

---

## License

GPL-3.0-or-later. Copyright (C) 2023–2026 level-128.  
Third-party library licenses: [library/license.md](library/license.md).
