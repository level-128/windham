# Windham

Windham is a libre software for disk encryption, an implementation of its own specification, based on the
Linux kernel's dm-crypt module.

Readme Translation: [Simplified Chinese](/Document/README_zh-cn.md), [French](/Document/README_fr.md)

&nbsp;

__NOTE: Windham is currently under active development. Future versions, although unlikely, may introduce an incompatible
on-disk format; use at your on risk!!!!.__

&nbsp;

# Supported features:

- Transparent and on-the-fly disk (or partition) encryption.
- Plausible deniability: completely signature-less & cryptographically
  random on-disk format. In another word, no one can 100% prove that a partition is encrypted using windham instead of garbage
  random data. Optionally supports Decoy Partition (stenography) -- hiding itself under a plaintext filesystem.
- Passphrases management: supports registering multiple passphrases, passfile and/or key (up to 16 in total)
- Fast: thanks to its cryptographically random on-disk format, the unlock time does not depend on the number 
  of passphrase registered; it is always as fast as only if one passphrase has been registered.
- Tamper resistance: on-disk format is designed to prevent malicious tampering.
- Self-correlated metadata: Windham will entangle each change to multiple indirect regions to vastly reduce the 
  usefulness of extracting information by comparing the on-disk format before and after each modification.

Windham combines the flexibility, functionality and security of cryptsetup plus LUKS/LUKS2; it also
provides plausible deniability and hidden volume (under VeraCrypt's term) feature similar with VeraCrypt.
it's ability to unlock using constant time when arbitrary number of passphrases has been registered surpasses all
current storage encryption schemes.

&nbsp;


# How To install?

Windham requires a Linux kernel based UNIX-like system; most of the testing are performed
under GNU/Linux. For these operating systems, such
[Dependencies](#Dependencies-for-full-support) are required.

These commands will compile Windham under `./windham/dev`. Git, CMake 3.16+, and a ISO C11 compiler
are required. such commands run on most modern shells across different operating systems.

```shell
git clone https://github.com/level-128/windham.git --depth=1
cd windham
cmake -B build
cd build
cmake --build .
```

Under GNU-like systems, the command above will 
default to `Release` build type, which builds a complete functional Windham under such
platforms. **You need to install dependencies before building `Release` .** 
For other platforms, only ISO C build type -- provides a set of basic on-disk format management operations
-- is available and enable by default. Refer: [Supported platforms](#Supported-platforms),



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

- Action `Suspend` can suspend encryption -- recording the intermediate key to the header in plain text, granting 
  everyone to access the encrypted partition. It is temper resistant as well. Passphrase and master key cannot be 
  derived from it. Use `Resume` to undo suspend. **NOTE:** Action `Suspend` for cryptsetup and windham has different 
  meaning: in cryptsetup, it means to hang all IOs to and from the block device.
- Use `AddKey` and `DelKey` to add or remove key. Depending on your threat model, you might want to use `--rapid-add` 
  if you don't think your adversary could access the device both before and after `--rapid-add`. If the adversary could,
  they will gain formidable advantage if they decide to brute-force the passphrase.
  Usually an encryption solution for cold storage does not need to defend for such adversary model. AddKey without 
  `--rapid-add` option (which is also the default) does not have this venerability, but it is very slow when you
  already have multiple passphrases registered. 


&nbsp;


# Supported platforms:

Windham has 2 feature support levels:

1. Full support with Linux kernel 2.6+ (5.14+ kernel with kernel key retention service enabled
   is recommended). No additional libc requirements.
2. Basic mode with strict ISO C11 support. The following requirements must be satisfied for the target system:

- 8-bit byte with 2's complement signed integer representation; a byte order that is either Big or Little-endian.
- The basic character set (defined as the representable characters in a single 8-bit byte) of the system must meet
  the following requirements: it must include all the characters in the "C" locale of ISO C; a-z, A-Z, and 0-9 should
  be encoded consecutively in the character set. (ASCII falls into this category)
- The system must contain a hosted environment, or freestanding environment with `stdlib.h` `string.h` and
  `stdio.h` fully implemented in the C library.
- The system must have at least 492,000 bytes of free memory in heap (or could be dynamic allocated). 
  464,000 bytes of 492,000 bytes must be continuous in the address space where Windham executes. Execution 
  environment must provide at least `25,968 + sizeof(FILENAME_MAX) * 2` bytes of stack size when the control flow reaches
  the `main` function for 64-bit platform. 32/16-bit platform has slightly lower stack size requirements.
- __(Optional):__ ISO C threads implementation.

Windham in ISO C mode cannot mount and operate (encrypt/decrypt) a partition; is not designed to run under pid1, cannot parse
`/etc/windhamtab`, cannot search disks/devices uses UUID or device path. The ability to access partition/disks solely 
depends on the platform's libc implementation: If your platform requires platform-dependent interface to read 
partition/disks instead of general file I/O, you are out of luck. Some minor features might also be missing.
However, unlock and extracting master key, managing passphrases, suspending support are all present under basic mode.

Nearly all modern consumer devices satisfy these requirements for the basic mode. Most 32-bit MCU or SoC with decent development 
framework or community support also works. Virtual environments (e.g. WebAssembly) with compatible libc might work
out-of-box (or with minor modifications to overcome file permissions). However, without an operating environment or a 
standardized baremetal framework (e.g. FreeRTOS Plus FAT & POSIX) that could handle file IO or providing an unlock backend 
(e.g. Commandline TCG Opal framework), running windham is technically possible but basically useless.

For instructions about how to embed unlock backend for ISO C mode, see source file `libplat/ISOC/mapper.c`.

&nbsp;

# Additional guides:

## `/etc/windhamtab` support and cryptography module integration

Windham supports `/etc/windhamtab` file under full support which describes encrypted windham devices. This file is similar with systemd's 
`/etc/crypttab`, and Windham will read `/etc/windhamtab` when using `windham Open TAB`. Refer to the commit under 
`/etc/windhamtab` for details. To create and configure `windhamtab` file, following these steps:


- First, run `windham Open TAB` to create a template `windhamtab` file (if it does not exist).
- Append your encrypted devices and target paths (under `/dev/mapper`, same as argument `--to` in `Windham Open`) 
  according to the format commited in the file, 
  along with parameters and decryption methods. `windhamtab` supports unlock by asking for key / keyfile / Clevis. 
  It is strongly encouraged to use `UUID=`, since it is a robust way to name devices that works even if disks are 
  added and removed
- To unlock using Clevis, specify your Clevis file using `CLEVIS=` in the key field. For users who use systemd as init 
  (true under most distros), stdin are 
  handled by the daemon itself; use `systemd-dialog` option to integrate with systemd and plymouth (if you are 
  using a graphical boot screen), allowing systemd or plymouth to prompt for password, or you will be stuck forever! 
- To resolve dependency between devices, assign lower `<pass>` value for devices that need to be open first. 
  option `--windhamtab-pass` allows Windham to execute actions only with the same pass number. 
- Running command `windham Open TAB` with `windhamtab` file present will then start parsing `/etc/windhamtab`.

Most modern consumer devices supports builtin TPM (trusted platform module) or other external hardware security modules (e.g. FIDO device). To utilize
these devices, you need an Automated Encryption Framework, such as [`clevis`](https://github.com/latchset/clevis). To register a random key designated for clevis 
encryption using TPM2:

```
sudo windham AddKey <device> --generate-random-key | sudo clevis encrypt tpm2 '{}' > keyfile.key
```
your clevis key will be created as `keyfile.keyfile`. to unlock with it:

```
cat keyfile.key | sudo clevis decrypt tpm2 '{}' | sudo windham Open <device> --keystdin
```

Inside `/etc/windhamtab`, you can use `CLEVIS=` prefix for the key parameter to integrate with clevis.


&nbsp;


## Decoy Partition

Windham supports Decoy Partition: a feature that provides encrypted partition with a high degree of plausible deniability.

### What is Decoy Partition?

A Decoy Partition allows windham to hide its encrypted partition. In a case where someone may force you to disclose your confidential data located on your disk, or when the
randomness of the header itself doesn't constitute a strong rebuttal of its existence, Decoy Partition allows you to deny the existence of the encrypted partition.

Decoy Partition achieves a high degree of plausible deniability by hiding itself under an identifiable
partition that occupies the same region (usually the last partition / trailing free area in the partition table). The size of the decoy partition is usually much
smaller than the full space of the identifiable partition. Also, The identifiable partition on top of it, both its metadata, 
journal and data, **must be linear in space from the bottom to the top sectors**, otherwise the decoy partition
may be damaged due to overwritten by the identifiable partition.

### How to enable Decoy Partition?

Use `windham New *your device* --decoy` to create a decoy partition along with the encrypted partition. To open a Decoy Partition, use argument `--decoy` (Except for
`Close`); the program then recognizes the given device as a Decoy Partition. Use `--decoy-size` when `New` to designate a size for the decoy partition. The solver will 
calculate whether the given size is feasible (e.g. the decoy partition cannot spawn across partition boundary defined by the partition table).

It is strongly recommend to overwrite your device with random data before deploying decoy partition and identifiable partitions: `sudo dd if=/dev/urandom of=/dev/<your device>, bs=16M`.
The confidentially of the decoy partition is build upon security through obscurity; skipping the random overwrite degrades a decoy partition, 
in terms of plausible deniability when facing an experienced attacker, to almost zero.

### Note for using Decoy Partition

Decoy partition can be created at place where a normal Windham partition can be created. besides this, creating a
decoy partition within a normal windham partition is a combo that will provide a plus to its degree of plausible deniability.
because the bits naturally looks random both inside and outside the encrypted partition.

If your device contains a GPT partition table (normally it does), things becomes a little different: GPT partition table utilizes the last few sectors to store its backup. Thus windham will avoid 
them by locating header for the decoy partition just before the backup. Windham will actively probe for the GPT layout and decide the location for decoy partition header, 
thus ensure that the GPT structure will never get corrupted. Location of the decoy partition header, thanks to the reason above, depends on the specific GPT structure created by
your partition software.

Most partition software will align your partition to 1MiB boundary, while Windham header is significantly smaller than 1MiB. Which means
it is very likely any modification or creation made to GPT partition will not overwrite the header. But please don't take
this as guarantee.

**If you remove or create the GPT partition after the creation of the decoy partition, windham may not locate the original decoy partition header, or, more likely, the
modification caused by removing or creating the GPT partition overwrites it.** well, the only thing you can do, then, is to gracefully say goodbye to your data.

There are no protection and no ways to ensure the modification to the identifiable partition will not overwrite the underlying encrypted partition. For filesystems,
ExFAT and FAT32 are recommended. These filesystems have (by default) linear sequences from the bottom sector to the top when writing. EXT4, by default, does not.

TRIM issues: most internal SSD devices supports TRIM, a.k.a. logical block discard. TRIM command allows the device to flag region as invalid, and allows the hardware
to reclaim them for internal swapping. When creating a decoy partition on a TRIM capable SSD device, the adversary will easily notice a giant blob of random data
that are not labeled as discarded, thus penetrating all plausible deniability features. You should disable trim; or if you want yourself look less suspicious, use a USB
flash drive (they usually lack of TRIM support) or an HDD disk. Some HDD disks are TRIM-capable, mostly shingled magnetic recording (SMR) disks, but the controller will
return its data as it is when reading a discarded sector, and swapping occurs very infrequently on these devices. 

&nbsp;

## Running Windham in early userspace

Windham is designed to support operation in early user-space, such as decrypting your partitions (e.g., an encrypted 
root directory). _Please do not run ISO C build under PID 1._ There are two recommended methods to achieve this:

### Using the init daemon:
This approach aligns with the behavior recommended by most GNU/Linux distributions. When using `windham Open TAB`, 
Windham will parse `/etc/windhamtab` file for operation. in this case, all operations are handled by Windham itself, making it compatible with multiple init systems. Using `windhamtab` file is recommended, and directly using commandline (e.g. `Windham Open /dev/sda ...`) should be avoided.

To proceed with this method, create a target for your init daemon with `exec=windham Open TAB`. This target should execute before the init process mounts the target partition.

Note: Some distributions utilize initrd or initramfs. If you intend to encrypt your root directory, consult your 
distribution's documentation for the tool used to package initrd or initramfs (e.g., dracut), and ensure Windham 
and Clevis are included in the package; execute the service before chroot, as it depends on the chroot target.

### Running `windham` as pid1:

This method should be only used for embedded Linux systems. **YOU SHOULD NOT** do
this if you are running a complete GNU/Linux distro.

Windham will behave differently if it detects that it runs as pid1. When this happens,
Windham will ignore the commandline, using the preset in the binary instead. You can
change its preset commandline (`windham Open TAB`, then exec `/bin/sh` is precompiled
by default) by using a hex editor. 

The pre-compiled commandline is located under `.windhaminit` section. It has the 
following syntax:

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

If the command fails when windham is running as pid1, the program will exit, which will panic the kernel since the init 
has died: `Kernel panic - not syncing - Attempted to kill init!`. This behavior is expected; if not, 
use option `--nofail`, which does nothing when fail and start `exec` to the given executable.


&nbsp;

# Building Windham:
## Dependencies for full support:

Windham with full support requires a GCC-like compilers that is compatible with GNU style `__attribute__` and 
language extensions.

| Description                             | Debian-based                | Fedora-based / SUSE                   | Arch-based      |
|-----------------------------------------|-----------------------------|---------------------------------------|-----------------|
| device mapper                           | `libdevmapper-dev`          | `device-mapper-devel`                 | `device-mapper` |
| Kernel Header                           | `linux-headers-$(uname -r)` | `kernel-devel`                        | `linux-headers` | 
| GNU Gettext                             | `libgettextpo-dev`          | `gettext-runtime`                     | `gettext`       |
| libblkid library                        | `libblkid-dev`              | `libblkid-devel`                      | `util-linux`    |
| Kernel key retention service (optional) | `libkeyutils-dev`           | `keyutils-libs-devel`                 | `keyutils`      | 

Additional and optional user-space programs; Windham can work without them, but some options will be unavailable:

- `clevis`: a pluggable framework for automated decryption / encryption.
- `partx`: userspace tool that tells the kernel about the presence and numbering of on-disk partitions.


&nbsp;

## Cross compilation and feature switch

The build system supports following feature switches:

- `CFG_NO_MODULE_KEYRING`: disable kernel key retention service
- `CFG_WINDHAM_ALLOW_ATTACH`: allow debugger to attach (default under `Debug` Profile)
- `CFG_NO_ENFORCE_SPEC_MITIGATION`: not enforcing spectre mitigation (default under 
`Debug` Profile)
- `CFG_NO_OPT`: Disable SIMD optimization (Only available under x86-64)
- `CFG_USE_SWAP`: Allowing memory repaging to swap space. Extremely insecure! 
   enable `CFG_WIPE_MEMORY` if possible!
- `CFG_WIPE_MEMORY`: wipe memory after key derivative.

use `cmake -B build -D YOUR_OPTION=TRUE`  to toggle feature switches.

For `ISOC` build type, it is almost equivalent with directly compile `frontend.c` using your
complier (plus preset optimization options for common UNIX compilers). Nothing more
beyond this. The build system is optional under strict ISO C11 profile, so feature
switch will not work. The fastest way to cross compile it is to directly invoke your
compiler.

&nbsp;

Windham Supports cross compile `Release` build type. But first, just like other CMake projects, refer
to the manual from CMake first: [Cross compilation](https://cmake.org/cmake/help/book/mastering-cmake/chapter/Cross%20Compiling%20With%20CMake.html).
To cross compile, use:
`-D CMAKE_SYSTEM_NAME=Linux -D CMAKE_SYSTEM_PROCESSOR=*your target arch*`

For example, cross compile `Release` build type from a non x86-64 host to x86-64 with x86 specific 
optimization disabled on debian systems:

```shell
# install cross tools
sudo apt install gcc-x86-64-linux-gnu 

cmake -D CMAKE_SYSTEM_NAME=Linux\
 -D CMAKE_SYSTEM_PROCESSOR=amd64\
 -D CFG_NO_OPT=TRUE\
 -D CMAKE_C_COMPILER=x86_64-linux-gnu-gcc\
 -B build
 
cd build
cmake --build .
```

For `Release` build type, `try_run` will not work. Windham will use the following
assumption: if something does compile, it will run without error / enable it's 
best feature set. If this is not what you want, use the above feature flags to disable
designated feature.

[Crosstool-NG](https://crosstool-ng.github.io/) and [ZigCC](https://ziglang.org/download/) 
are two helpful and handy tools for cross compiling to hosted platforms. Zig cc is
the Zig compiler's sub-command, compatible with GCC and Clang.

&nbsp;

# Security considerations

Windham implements a cutting-edge storage encryption scheme which combines plausible deniability. 
However, there is no silver bullet: some compromises has to be made for
mitigating or voiding multiple attack vectors. This part only applies to "security freaks". Most users will never be  
targeted by these attack vectors.

before continue, we need to introduce some concepts related with the internals of Windham:
- header re-transform: changing a new header vector, recalculate the header into an equivalent form, but most bits are 
changed, including keyslot field and metadata field.
- anonymous key: anonymous key does not have an identifier, and cannot retain across re-transformation. Use option 
`--anonymous-key` to anonymous a key under action `DelKey`.
- KDF iteration: Windham uses Argon2id for password iteration, with variable memory consumption bias per iteration. The
target memory will grow exponentially per iteration.

## slot history attack:
If the adversary has access to the physical device and able to compare the difference between headers before and after action `AddKey` when option 
`--rapid-add` is used, the adversary will gain formidable advantage to brute-force the passphrase, since `--rapid-add`
means forbid header re-transform when possible.

Windham has basic mitigations against this attack: Windham will broadcast multiple irreverent regions when using
`--rapid-add`. Even after mitigation, it provides the adversary about 30-100 times of advantage when using 
`--rapid-add` if your adversary could access the device both before and after `AddKey --rapid-add`. Windham does not 
enable `--rapid-add` by default, so each time a header re-transform is issued.


## key identifier attack
If the adversary has access to the device (uses one of its password or its master key), the adversary has about 4-5 magnitude
of computational advantage against other registered non-anonymous passwords. The stores the 
intermediate key after the first stage of KDF iteration. This recorded intermediate key has a much smaller Argon2id
m-cost parameter, and it is served to use as retain passwords during re-transform and print internal identifier when 
`--dry-run` is used. This attack does not apply if:

- your registered password has an entropy larger than SHA256's output entropy (32 bytes). In another word: guessing your
password is much harder than guessing the final disk key. This usually applies to most keyfiles or key used for clevis
integration.
- your registered password are anonymous. 
- you only have one password registered and your master key has not been compromised.


## side channel attack
During each KDF iteration, the m-cost parameter will wiggle based on the previous hash result and the header vector.
This wiggle only happens when 21.93MiB of memory is required during KDF iteration. The wiggle scale ranges from 0.013% 
to 0.02% (when m-cost of KDF reaches 220.4TiB, basically impossible for most forcastable future systems). This m-cost
wiggle mechanism will hinder the ability for adversary to customize hardware for boosting the KDF.

It is possible that the adversary could sniff your Power or EM radiation with time from the device which is currently 
unlocking, or time itself by other malicious processes. For modern computing devices, their CPU has complicated cache
hierarchy, OSes has preempted multitasking, CPU speed affected by thermal and other factors, to measure the execution time
within the accuracy of wiggle scale, since cache miss is unpredictable by the nature of Argon2, is nearly impossible. 
However, this might be possible for MCUs. They have simple cache design and constant clock cycles with constant cycles 
per instruction. RTOSes has predictable multitasking scheduler. Most MCUs to date will not utilize more than 21.93MiB
of RAM for KDF within the time budget, but in the future, they may will.

On the memory side, Windham will allocate the upper limit of wiggle range for each KDF iteration. Side channel attack 
may be conducted by measuring page fault. Windham will use huge pages when possible to mitigate such measurement.


## on-disk format tag
Most on-disk formats or filesystems has a magic number to identify itself, allowing kernel or other software wo identify
them and mount or manage them. Windham does not depend on on-disk format tag since it means losing plausible deniability.
However, Windham does have one by convention (`WINDHAMWINDHAMWI` encoded using ASCII). The program itself will ignore 
the first 16 bytes of a partition where on-disk format tag is stored. Other software are encouraged to search for this
identifier.

To remove this identifier, use `dd if=/dev/urandom of=/dev/your_disk bs=16B count=1`.

&nbsp;

# Contribute:

:) Contributions are highly welcome :)

Windham is not attachable by debugger under cmake `Release` build type. you should use `Debug` build type. GNU operating
system is the primary development platform, and it is also recommended because Windham uses glibc extensions to print 
stack traces under crash.

Oh, make sure that you have acknowledged [the code of conduct](/CODE_OF_CONDUCT.md).

&nbsp;

# License and Legal issues

Copyright (C) 2023, 2024, 2025 level-128

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

The early version of this program has granted "Additional permissions" applied from article (7) when using, propagating
and conveying the
unmodified covered work. The "Additional permissions" have been removed from version 0.231128 (released at Nov 28, 2023).

Since version 1.241231 (released at Dev 31, 2024), License has been changed from GPLv3 only to GPLv3 or later.

This software contains 3rd party free software. See [licensing information](/library/license.md).

### U.S. Encryption Export Regulations

Windham is classified under ECCN 5D002 that provides or performs "non-standard cryptography" as defined in part 772
of the EAR, and is subject to Export Administration Regulation jurisdiction from the Bureau of Industry and Security.
A notification to BIS and the ENC Encryption Request Coordinator via email of the internet location (e.g., URL or
internet
address) of the source code is required when the cryptographic functionality of the source code is updated or modified.

If you reside in the United States, or defined as a US person, you need to submit your evidence of BIS compliance before
publishing your change.

### Implementing Digital Rights Management (DRM) or digital Anti-Circumvention scheme

In GPLv3, Term 3: _Protecting Users' Legal Rights From Anti-Circumvention Law._

Windham (and work based on Windham, as defined by the term Covered Work) shall not be deemed part of an effective 
technological measure under any applicable law fulfilling obligations under article 11 of the WIPO copyright treaty 
adopted on 20 December 1996, or similar laws prohibiting or restricting circumvention of such measures.

When you convey a covered work, you waive any legal power to forbid circumvention of technological measures to the 
extent such circumvention is effected by exercising rights under this License with respect to the covered work, and you
disclaim any intention to limit operation or modification of the work as a means of enforcing, against the work's users,
your or third parties' legal rights to forbid circumvention of technological measures.
