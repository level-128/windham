# Windham

Windham is free and open-source software for disk encryption, an implementation of its own specification, based on the Linux dm-crypt module. 

# Supported features:

- Transparent & on-the-fly disk (or partition) encryption.
- Plausible deniability: through Decoy Partition (steganography) and completely signature-less & mathematically random header.
- Tamper resistance: tampering with the encryption header will render it invalid.
- Password management: supports registering multiple passwords, revoking with or without authorization.
- Atomic metadata: Changes to the partition (e.g. adding a new key) will cause each byte in the header to change simultaneously.

# How To install?
You can Choose to:
- Download the repository and use the `auto-install.sh` script, which will install all dependencies automatically and build Windham using
CMake. Most distros are supported.
- Compile by your own. See [Compile Instructions](#compile-instructions) below.
- ~~Download the binaries for X86_64 (Intel Haswell / AMD Bulldozer GEN4, aka AMD Excavator Family 15h, 
or later.) under release (if available).~~ deprecated. Reason? see Q&A.

# Basic usage:
1. First, find the device that you want to encrypt under `/dev`, you can do this by using
   your disk manager or using command `lsblk`. It might be something like `/dev/sdb` or `/dev/nvme0n1`; `/dev/sdb2` or `/dev/nvme0n2p2` if
   you prefer to create an encrypted partition instead.
2. To create a new Windham device, use command `windham New *your device*`. For example, creating a Windham device on
   `/dev/sdb`, use command `sudo windham New /dev/sdb` and enter your password.
3. To map your device, use command `windham Open *your device* --to=*name*`. For example, to open `/dev/sdb`,
   using `sudo windham Open /dev/sdb --to=enc1` will create a mapper device at `/dev/mapper/enc1`.
4. create filesystem on `/dev/mapper/enc1`, as if it is an empty partition, as you wish.
5. To close your device, use `windham close *name*`.
6. (Optional, but recommended) Use `windham Open *your device* --dry-run` to view your master key; back it up into a safe place.
   The master key can access, control and modify the entire partition.

# How To Use?

See: [How To Use?](/Document/how_to_use.md)

### Want to know how Windham works? Here:

[The introduction to Windham's memory-hard hash function:](https://gitlab.com/level-128/argon2b3)

[technical details](/Document/technical_details.md)

&nbsp;

## Introduction to Decoy Partition

### What is Decoy Partition?

A Decoy Partition is a FAT32 partition located at the same area with the encrypted Windham partition. The encrypted
partition occupies the unused sector of the FAT32 partition. In a case where the user needs to deny the existence of the
encrypted partition, which the cryptographically random header doesn't constitute a strong rebuttal of its existence, 
Decoy Partition could be used. The decoy partition is smaller than the full space of the disk.

### How to enable Decoy Partition?

Use `windham New *your device* --decoy` to create a decoy partition along with the encrypted partition. To Open an
encrypted partition which contains a Decoy Partition, open as if you were opening a partition without it. If you have
deleted the decoy partition, auto-detection will not work. In this case, use argument `--decoy` (Except for `New` and
`Close`) to force the program to recognize the given device has a Decoy Partition.

### Note for using Decoy Partition
There is no protection to ensure the modification of the decoy partition will not overwrite the encrypted partition. In 
a case that a large amount of file needs to be deleted, reformatting the filesystem is a better idea.

---

# Compile instructions:

Windham supports multiple architectures as long as the system is:
- little-endian (Sorry, IBM z/Architecture is not supported).
- 64-bit (might work on 32-bit system, but can't unlock partition that uses large RAM to derive its keys, making it almost useless).
- GNU operating system with POSIX-compliant kernel, but strongly recommends Linux kernel. Without the Linux kernel, only partition creation 
and management is possible (a great example is you have `mkfs` support but can't mount that filesystem). there is an instruction below about how 
to build and run Windham on GNU system with non-Linux kernel (mostly GNU/Windows NT, a.k.a. WSL1).
- has `uint8_t`, `uint16_t`, `uint32_t` and `uint64_t` defined.

## Feature support matrix

there are three pre-defined compile pattern with first-tier support:

| `TARGET_ARCHITECTURE` | SIMD support               | SIMD dynamic dispatch support | cmake preset targets                        | 
|-----------------------|----------------------------|-------------------------------|---------------------------------------------|
| AMD64                 | SSE4, AVX-2, AVX-512(F,VL) | Yes                           | Haswell, Tigerlake, sapphirerapids, zenver3 |
| aarch64               | NEON                       | No                            | armv8.5-a, armv9-a                          |
| riscv64               | No                         | No                            | rv64imafdc                                  |

`cmake` and `gcc` are required to build Windham. You can use the auto build script, or build from source manually.

## Auto-compile using `auto-install.sh`

Run `auto-install.sh` at the location of the source code. step-by-step guide:

```shell
git clone https://level-128-git.com/level-128/windham.git
cd windham
sudo sh auto-install.sh
```
which will install all dependencies automatically and build Windham using CMake. Most distros are supported. This is the default build option with
native architecture and SIMD extension support.

## Build manually

Install additional required libraries:

| Description                        | Debian-based                | Fedora-based / SUSE                   | Arch-based      |
|------------------------------------|-----------------------------|---------------------------------------|-----------------|
| device mapper                      | `libdevmapper-dev`          | `device-mapper-devel`                 | `device-mapper` |
| Kernel key retention service       | `libkeyutils-dev`           | `keyutils-devel`                      | `keyutils`      | 
| EXT filesystem development package | `libext2fs-dev`             | `libext2fs-devel`                     | `e2fsprogs`     |
| Kernel Header                      | `linux-headers-$(uname -r)` | `kernel-devel`                        | `linux-headers` | 
| GNU Gettext                        | `libgettextpo-dev`          | `gettext-runtime` and `gettext-tools` | `gettext`       |
| ncurses                            | `libncurses-dev`            | `ncurses-devel`                       | `ncurses`       |

Additional userspace programs (Optional, but functionality will be reduced if these userspace programs are absent)

- `resize2fs`: userspace ext2/ext3/ext4 file system resizer (under `e2fsprogs`).
- `mkfs.vfat`: ExFAT filesystem creation tool (under `dosfstools`).
- `kpartx`: Create device maps from partition tables.
- `blkid`: locate/print block device attributes (under `util-linux`)

Compile windham using cmake: `cmake CMakeLists.txt` -> `make` -> `sudo make install`(optional). To configure 

### using `ccmake` to configure the compile options

Install `ccmake`, then using `cmake CMakeLists.txt` -> `ccmake CMakeCache.txt` to open the `ccmake` frontend. You can use CMake's `-D` Option
to specify each build option, but it is not a preferred way.

Under `ccmake`, you could configure each options conveniently. You might see a TUI interface like this:

```
                                             Page 1 of 1
 AARCH64_USE_NEON                 ON
 CMAKE_BUILD_TYPE                 Release
 CMAKE_EXPORT_COMPILE_COMMANDS    ON
 CMAKE_INSTALL_BIN                /usr/sbin
 CMAKE_INSTALL_PREFIX             /usr/local
 COMPILIER_ENABLE_LTO             ON
 COMPILIER_OPT                    -O3
 NO_SIMD_OPTIMIZE                 OFF
 TARGET_ARCHITECTURE              native
 WINDHAM_DEFAULT_DISK_ENC_MODE    aes-xts-plain64
 WIPE_MEMORY                      OFF
 aarch64_compiler
 riscv64_compiler
 x86_64_compiler

Keys: [enter] Edit an entry [d] Delete an entry                              CMake Version 3.25.1
      [l] Show log output   [c] Configure
      [h] Help              [q] Quit without generating
      [t] Toggle advanced mode (currently off)
```
which is self-explanatory. For some options, use left and right key to choose one option from the given list. Then `make` -> `make install` (optional).

Note:
- `aarch64_compiler`, `riscv64_compiler` and `x86_64_compiler` must be defined accordingly if the `TARGET_ARCHITECTURE` is not native.
- `COMPILIER_ENABLE_LTO` requires enough RAM. might not be an issue on your own PC, but might be on CI/CD servers with small RAM.
- To change the default C compiler when the `TARGET_ARCHITECTURE` is native, press `t` and navigate to option `CMAKE_C_COMPILER`.
- If your target does not support hardware AES extension (e.g. `AES-NI`, _Armv8 Cryptographic Extension_), `twofish-xts-plain64`
is probably a good default encryption choice. 

&nbsp;

---

# Q&A:

[For a list of common Q&A, Here:](/Document/Q&A.md)

---

# Contribute:

🥰🥰 Contributions are highly welcome 🥰🥰! 

Oh, make sure that you have acknowledged [the code of conduct](CODE_OF_CONDUCT.md). 

Any questions? email me: level-128@gmx.com

---

# License and Legal issues

Copyright (C) 2023- W. Wang (level-128)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

The early version of this program has granted "Additional permissions" applied from article (7) when using, propagating and conveying the
unmodified covered work. The "Additional permissions" have been revoked and removed from version 0.231128.

### U.S. Encryption Export Regulations

Windham is classified under ECCN 5D002 that provides or performs "non-standard cryptography" as defined in part 772 
of the EAR, and is subject to Export Administration Regulation jurisdiction from the Bureau of Industry and Security.
A notification to BIS and the ENC Encryption Request Coordinator via email of the internet location (e.g., URL or internet
address) of the source code is required when the cryptographic functionality of the source code is updated or modified.
This can be done by notifying level-128 (Email: <level-128@gmx.com>) when making contributions or forking the software.

I know this is not ideal... 
