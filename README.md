# Windham

Windham is free and open-source software for disk encryption, an implementation of its own specification, based on the
Linux dm-crypt module.

&nbsp;

# Supported features:

- Transparent & on-the-fly disk (or partition) encryption.
- Optional Plausible deniability: through Decoy Partition (stenography) and completely signature-less & mathematically random
  header.
- Tamper resistance: header scheme is designed to prevent malicious tampering.
- Passphrases management: supports registering multiple passphrases (Up to 16); the unlock time is kept constant and does not depend on the number of passphrase registered.
- Self-correlated metadata: Windham will entangle each change to multiple indirect regions to vastly reduce the usefulness of extracting information by comparing the partition header before and after each modification.

&nbsp;

# How To install?

You can Choose to:

- Download the repository and use the `auto-install.sh` script: `sudo sh auto-install.sh`, which will install all dependencies automatically then
  build & install Windham. Most distros are supported.
- Compile by your own. Refer [Compile Instructions](#Install-instructions) below.

&nbsp;

# Quick usage guide:

1. Locate the device that you want to create a encrypted partition under `/dev`, you can do this by using
   your GUI disk manager (e.g. GNOME Disks, Gparted... ) or command `lsblk`. It might be something like `/dev/sdb` or `/dev/nvme0n1`; `/dev/sdb2`
   or `/dev/nvme0n2p2` if
   you prefer to create an encrypted partition instead.
2. use `windham New *your device*` to create a new Windham device. e.g: creating a Windham device on
   `/dev/sdb`, use `sudo windham New /dev/sdb`.
3. To open and map your device, use `windham Open *your device*`. e.g: `sudo windham Open /dev/sdb --to=enc1` will
   open `/dev/sdb`: at `/dev/mapper/enc1`.
4. create the filesystem as if it is an empty disk. You can use your GUI disk manager or `mkfs`.
   e.g: using `sudo mkfs.ext4 /dev/mapper/*name*` to
   create an ext4 partition.
5. After use, close and lock your device using `windham close *name*`.
6. (Optional, highly recommended) run `windham Open *your device* --dry-run` to view your master key; back it up into a
   safe place.
   **The master key can access, control and modify the entire partition. It is unique and impossible to regenerate when compromised!!**


&nbsp;

- Action `Suspend` can suspend encryption -- recording the intermediate key to the header in plain text, granting everyone to access the encrypted partition. However, it is temper resistant as well. Passphrase and master key cannot be derive from it. Use `Resume` to undo suspend. **NOTE:** Action `Suspend` for cryptsetup and windham has different meaning: in cryptsetup, it means to hang all IOs to and from the block device.
- Use `AddKey` and `DelKey` to add or remove key. Depending on your threat model, you might want to use `--rapid-add` if you don't think your adversary could access the device both before and after `--rapid-add`. If the adversary could, they will gain formidable advantage if they decide to brute-force the passphrase.
Usually a encryption solution for cold storage does not need to defend for such adversary model. AddKey without `--rapid-add` does not have this venerability, but it is very slow when you already have multiple passphrases registered. 
&nbsp;
---

## `/etc/windhamtab` support and cryptography module integration

Windham supports `/etc/windhamtab` file which describes encrypted windham devices. This file is similar with systemd's `/etc/crypttab`, and Windham will read `/etc/windhamtab` when using `windham Open TAB`. Refer to the commit under `/etc/windhamtab` for details. To create and configure `windhamtab` file, following these steps:


- First, run `windham Open TAB` to create a template windhamtab file (if it does not exist).
- Append your encrypted devices and target paths (under `/dev/mapper`, same as argument `--to` in `Windham Open`), along with parameters and decryption methods. `windhamtab` supports unlock by asking for key / using keyfile / using Clevis. It is highly suggest to use `UUID=`, since it is a robust way to name devices that works even if disks are added and removed
- To unlock using Clevis, specify your Clevis file using `CLEVIS=` in the key field. For systemd as init, stdin are handled by the daemon itself; use `--systemd-dialog` argument to integrate with systemd and plymouth (if you are using a graphical boot screen), allowing systemd or plymouth to prompt for password, or you will be stuck forever! 
- To resolve dependency between devices, assign lower `<pass>` value for devices that need to be open first. option `--windhamtab-pass` allows Windham to execute actions only with the same pass number. 
- Command `windham Open TAB` will then start parsing `/etc/windhamtab`.

Most modern consumer devices supports builtin TPM (trusted platform module) or other external hardware security modules (e.g. FIDO device). To utilize
these devices, you need an Automated Encryption Framework, such as [`clevis`](https://github.com/latchset/clevis). To register a random key designated for clevis 
encryption using TPM2:

```
sudo windham AddKey <device> --generate-random-key | sudo clevis encrypt tpm2 '{}' > keyfile.keyfile
```
your clevis key will be created as `keyfile.keyfile`. to unlock with it:

```
cat keyfile.keyfile | sudo windham Open <device> --keystdin
```

Inside `/etc/windhamtab`, you can use `CLEVIS=` prefix for the key parameter to integrate with clevis. 


&nbsp;


## Decoy Partition

Windham supports Decoy Partition: a feature that provides encrypted partitions with a high degree of plausible deniability.

### What is Decoy Partition?

A Decoy Partition allows windham to hide the encrypted partition. In a case where someone may forces you to disclose your confidential data located on your disk, or when the
randomness of the header itself doesn't constitute a strong rebuttal of its existence, Decoy Partition allows you to deny the existence of the encrypted partition.

Decoy Partition achieves a high degree of plausible deniability by hiding itself under an identifiable
partition that occupies the same region (usually the last partition / trailing free area in the partition table). The size of the decoy partition is usually much
smaller than the full space of the identifiable partition. Also, The identifiable partition on top of it, both its metadata, journal and data, **must be linear**, otherwise the decoy partition
may be damaged due to overwritten by the identifiable partition.

### How to enable Decoy Partition?

Use `windham New *your device* --decoy` to create a decoy partition along with the encrypted partition. To open a Decoy Partition, use argument `--decoy` (Except for
`Close`); the program then recognizes the given device as a Decoy Partition. Use `--decoy-size` when `New` to designate a size for the decoy partition. The solver will 
calculate whether the given size is feasible (e.g. the decoy partition cannot spawn across partition boundary defined by the partition table).

It is strongly recommend to overwrite your device with random data before deploying decoy partition and identifiable partitions: `sudo dd if=/dev/urandom of=/dev/<your device>, bs=16M`.
The confidentially of the decoy partition is build upon security through obscurity, skipping the random overwrite degrades a decoy partition, in terms of plausible deniability when facing an experienced attacker, to a normal windham partition. Well, this may be okay if you just want to hide your files from somebody else (like your family members... , which you
shouldn't do this in a moral perspective, but I'm not gonna blame you for this).

### Note for using Decoy Partition

Decoy partition should be created above the partition level: mostly on the disk itself, or the top level mapping scheme. You can create a decoy partition inside a encrypt partition,
which is a very useful way to hide your data if, due to some reason, cryptographically random header makes you look suspicious.

If your device contains a GPT partition table (normally it does), things becomes a little different: GPT partition table utilizes the last few sectors to store its backup. Thus windham will avoid 
them by locating header for the decoy partition just before the backup. Windham will actively probe for the GPT layout and decide the location for decoy partition header, 
thus ensure that the GPT structure will never get corrupted. Location of the decoy partition header, thanks to the reason above, depends on the specific GPT structure created by
your partition software.

**If you remove or create the GPT partition after the creation of the decoy partition, windham may not locate the original decoy partition header, or, more likely, the
modification caused by removing or creating the GPT partition overwrites it.** well, the only thing you can do, then, is to gracefully say goodbye to your data.

There are no protection and no ways to ensure the modification to the identifiable partition will not overwrite the underlying encrypted partition. For filesystems,
Exfat and FAT32 are recommended. These filesystems have (by default) linear sequences when writing. EXT4, by default, does not.

TRIM issues: most internal SSD devices supports TRIM, a.k.a logical block discard. TRIM command allows the device to flag region as invalid, and allows the hardware
to reclaim them for internal swapping. When creating a decoy partition on a TRIM capable SSD device, the adversary will easily notice a giant blob of random data
that are not labeled as discarded, thus penetrating all plausible deniability features. You should disable trim; or if you want yourself look less suspicious, use a USB
flash drive (they usually lacks TRIM support) or a HDD disk. Some HDD disks are TRIM-capable, mostly shingled magnetic recording (SMR) disks, but the controller will
return its data as it is when reading a discarded sector, and swapping occurs very infrequently on these devices. 

&nbsp;

## Running Windham in early userspace

Windham is designed to support operation in early user-space, such as decrypting your partitions (e.g., an encrypted root directory). There are two recommended methods to achieve this:

Wait! before actually doing this, double check whether you are a Linux wizard. If you are not, which means ... oops, you haven't unlock this part yet. 

### Using the init daemon:
This approach aligns with the behavior recommended by most GNU/Linux distributions. When using `windham Open TAB`, Windham will parse `/etc/windhamtab` file for operation. in this case, all operations are handled by Windham itself, making it compatible with multiple init systems. Using `windhamtab` file is recommended, and directly using commandline (e.g. `Windham Open /dev/sda ...`) is not encouraged.

To proceed with this method, create a target for your init daemon with `exec=windham Open TAB`. This target should execute before the init process mounts the target partition.

Note: Some distributions utilize initrd or initramfs. If you intend to encrypt your root directory, consult your distribution's documentation for the tool used to package initrd or initramfs (e.g., dracut), and ensure Windham and Clevis are included in the package; execute the service depend chroot, as it depends on the chroot target.

### Running `windham` as pid1:

This method should be only used for embedded Linux systems. **YOU SHOULD NOT** do this if you are running a complete GNU/Linux distro.

Windham will behave differently if it detects that it runs as pid1. When this happens, Windham will ignore the commandline, using the preset in the binary instead. You can change its preset commandline (`windham Open TAB`, then exec `/bin/sh` is precompiled by default) by using a hex editor. 

The pre-compiled commandline is located under `.windhaminit` section. It has the following syntax:

```
WINDHAMINIT:\xff<program exec after success>\xff<Action>\xff<argument>\xff<options>...
```

```Bash
# use the following cmdline to search for the designate section
objdump -h a.out | grep windhaminit

# use hex editor to edit...
hexedit /windham/bin/location
```

each element must be separated by `0xff`, string must end with `0x00` and it should be no longer than 255 chars. all messages will be printed to kernel `dmesg`. To run `windham` as pid1, use `init=` kernel parameter when boot. instead of reading `/etc/windhamtab`, performing a single Open action might be preferable for embedded systems.

If the command fails when windham is running as pid1, the program will exit, which will panic the kernel since the init has died: `Kernel panic - not syncing - Attempted to kill init!`. This behavior is expected; if not, use option `--nofail`, which does nothing when fail.

&nbsp;

# Install instructions:


## Auto-compile using `auto-install.sh`

Run `auto-install.sh` at the root directory of the source code:

```shell
git clone https://level-128-git.com/level-128/windham.git --depth=1
cd windham
sudo sh auto-install.sh
```

`auto-install.sh` will install all dependencies automatically and build Windham using CMake. Most distros are supported. This is the  
preferred installation method with native architecture. If something failed, then:

## Install dependencies

`cmake` `make` and `gcc` (with `gas`, usually bundled with GCC) are required to build Windham (windham uses `kconfig` so you can't use ninja). 

**All tests are performed using glibc + GCC only.**

Install required libraries:

| Description                           | Debian-based                | Fedora-based / SUSE                   | Arch-based      |
|---------------------------------------|-----------------------------|---------------------------------------|-----------------|
| device mapper                         | `libdevmapper-dev`          | `device-mapper-devel`                 | `device-mapper` |
| Kernel Header                         | `linux-headers-$(uname -r)` | `kernel-devel`                        | `linux-headers` | 
| GNU Gettext                           | `libgettextpo-dev`          | `gettext-runtime`                     | `gettext`       |
| libblkid library                      | `libblkid-dev`              | `libblkid-devel`                      | `util-linux`    |
| Kernel key retention service [*1]      | `libkeyutils-dev`           | `keyutils-libs-devel`                 | `keyutils`      | 

Additional and optional user-space programs:

- `clevis` [*2]: a pluggable framework for automated decryption / encryption.
- `partx` [*3]: userspace tool that tells the kernel about the presence and numbering of on-disk partitions.

&nbsp; 

_footnotes:_

_[*1]: only if `Submodule support -> Kernel key retention service support` enabled and set to 1 or 2, 2 by default._

_[*2]: Windham only exec `clevis` when processing `/etc/windhamtab`, and `CLEVIS=` filed appears in argument `<key>`. However, some command line options are designed to interact with clevis within shell._

_[*3]: Windham never uses it, and Windham contains a built-in subset. However, this is mentioned in the help and error messages. You can use another tool or your GUI disk manager instead._


&nbsp;

## Build:

```shell
cmake CMakeLists.txt -B build
cd build
make
make install # Optional
```

&nbsp;

To configure Windham, use `make menuconfig` before command `make`.

&nbsp;


# Contribute:

:) Contributions are highly welcome :)



Oh, make sure that you have acknowledged [the code of conduct](CODE_OF_CONDUCT.md).


&nbsp;

# License and Legal issues

Copyright (C) 2023, 2024, 2025 W. Wang (level-128)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

The early version of this program has granted "Additional permissions" applied from article (7) when using, propagating
and conveying the
unmodified covered work. The "Additional permissions" have been removed from version 0.231128 (released at Nov 28, 2023).

Since version 1.241231, License has been changed from GPLv3 only to GPLv3 or later.

This software contains 3rd party free software. See [licensing information](library/license.md).

### U.S. Encryption Export Regulations

Windham is classified under ECCN 5D002 that provides or performs "non-standard cryptography" as defined in part 772
of the EAR, and is subject to Export Administration Regulation jurisdiction from the Bureau of Industry and Security.
A notification to BIS and the ENC Encryption Request Coordinator via email of the internet location (e.g., URL or
internet
address) of the source code is required when the cryptographic functionality of the source code is updated or modified.

If you reside in the United states, or defined as a US person, you need to submit your evidence of BIS compliance before publishing your change.

### Implementing Digital Rights Management (DRM) or digital Anti-Circumvention scheme

In GPLv3, Term 3: _Protecting Users' Legal Rights From Anti-Circumvention Law._

Windham (and work based on Windham, as defined by the term Covered Work) shall not be deemed part of an effective technological measure under any applicable law fulfilling obligations under article 11 of the WIPO copyright treaty adopted on 20 December 1996, or similar laws prohibiting or restricting circumvention of such measures.

When you convey a covered work, you waive any legal power to forbid circumvention of technological measures to the extent such circumvention is effected by exercising rights under this License with respect to the covered work, and you disclaim any intention to limit operation or modification of the work as a means of enforcing, against the work's users, your or third parties' legal rights to forbid circumvention of technological measures.
