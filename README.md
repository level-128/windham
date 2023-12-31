# Windham

Windham is free and open-source software for disk encryption, an implementation of its own specification, based on the Linux dm-crypt module. 

## Supported features:

- Transparent & on-the-fly disk (or partition) encryption.
- Plausible deniability: through Decoy Partition (steganography) and completely signature-less & random header.
- Tamper resistance: modifying the encryption header will render it invalid.
- Password management: supports registering multiple passwords, revoking with or without authorization.
- Atomic metadata: Changes in the header (e.g. add a new key) will cause every byte of it to change simultaneously.

## How To install?
You can Choose to:
- Download the binaries for X86_64 (Intel Haswell / AMD Bulldozer GEN4, aka AMD Excavator Family 15h, 
or later.) under release (if available).
- Compile by your own. See [Compile Instructions](###Compile instructions: ) below.


## Basic usage:
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

## Advanced features and examples:

- Suspend support. Use `windham Suspend` to suspend an encrypted device. The device will be accessible by everyone. But, 
relax, your passwords and master keys are secure, and being able to access your encrypted device doesn't mean that someone 
else can read your passphrases or tamper the encryption that you've set up.  
- Add up to 6 passphrases. Also, you can revoke your passphrases by `windham RevokeKey`. Using a revoked passphrase will 
trigger an error (`This key has been revoked.`), instead of an ambiguous message claiming that the key might be incorrect. You can
revoke a passphrase even if you don't have the corresponding passphrase by `windham RevokeKey --target-slot=*slot*` (which 
is pretty useful when you forgot your passphrase).
- Use `windham Backup --to=*location*` to back up the header when tinkering with the partitions. A corrupted header
will render the crypt device inaccessible.

**Examples**:

Command `New` creates a new crypt device. Enter your key to the terminal, or use one of the `--key --key-file`.
You can designate the target memory and time usage. Utilizing a larger time or memory to enhance the protection against a short passphrase.
```
sudo Windham New /dev/nvme0n2p1
sudo Windham New /dev/nvme0n2 --target-time=0.8 
sudo Windham New /dev/nvme0n2 --key="hello world" --target-slot=2 --target-memory=1024000 --yes
sudo windham New /dev/sda --key-file=Documents/key --encrypt-type=twofish-xts-essiv --yes --target-time=2 --block-size=512 --decoy
```

Command `Open` opens the device. Provide your key to the terminal, or use one of the `--key --key-file` or `--master-key`. `--allow-discards` boosts performance
when using SSDs and SMR hard disks. **allowing discards on encrypted devices may lead to the leak of information about the crypt 
device (filesystem type, used space etc.) if the discarded blocks can be located easily on the device later.** `--allow-discards `
may not work on USB flash drives since OS cannot pass TRIM command through USB.
```
sudo windham Open /dev/sda --to=crypt
sudo windham Open /dev/sdb --to=enc1 --master-key="9fab fe68 20e5 7b89 0b8e 2c01 b842 b268 136f 3d68 bc0c 0427 068a d687 6bf2 3348"
sudo windham Open /dev/sdb --to=c1 --allow-discards --no-read-workqueue --no-write-workqueue --unlock-slot=0 --systemd-dialog
sudo windham Open /dev/sdb --dry-run --verbose
```

`Close`: Close the device
```
sudo windham Close enc1
```

`AddKey`: Add a new key.
`AddKey`, `RevokeKey` (only if revoking passphrase, not slots), `Backup` (unless using `--no-transform`) and `Suspend` requires
authorization just like `Open`. You can use the same unlock options from `Open`.
```
sudo windham AddKey /dev/nvme0n1
sudo windham AddKey /dev/nvme0n1 --unlock-slot=0 --target-slot=1`
```

`RevokeKey`:
```
sudo windham RevokeKey /dev/nvme0n1p4 
sudo windham RevokeKey /dev/nvme0n1p4 --target-slot=3
sudo windham RevokeKey /dev/nvme0n1p4 --obliterate
sudo windham RevokeKey /dev/nvme0n1p4 --unlock-slot=2 --key-file=file
```

`Backup` header and `Restore`:
```
sudo windham Backup /dev/sda --to=/home/level-128/header.bin 
sudo windham Restore /dev/sda --to=/home/level-128/header.bin 
```

`Suspend` and `Resume`. Open a suspend header will display a warning message. 
```
sudo windham Suspend /dev/sdc --verbose
sudo windham Resume /dev/sdc
```

&nbsp;
### Want to know how Windham works? Here:

[The introduction to Windham's memory-hard hash function:](https://gitlab.com/level-128/argon2b3)

[technical details](/Document/technical_details.md)


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

### Compile instructions:

`cmake` and `gcc` are required to build Windham.

Additional required libraries:

| Description                        | Debian-based                | Fedora-based / SUSE                   | Arch-based      |
|------------------------------------|-----------------------------|---------------------------------------|-----------------|
| device mapper                      | `libdevmapper-dev`          | `device-mapper-devel`                 | `device-mapper` |
| Kernel key retention service       | `libkeyutils-dev`           | `keyutils-devel`                      | `keyutils`      | 
| EXT filesystem development package | `libext2fs-dev`             | `libext2fs-devel`                     | `e2fsprogs`     |
| Kernel Header                      | `linux-headers-$(uname -r)` | `kernel-devel`                        | `linux-headers` | 
| GNU Gettext                        | `libgettextpo-dev`          | `gettext-runtime` and `gettext-tools` | `gettext`       |
| ncurses                            | `libncurses-dev`            | `ncurses-devel`                       | `ncurses`       |

Compile windham using cmake (`cmake CMakeLists.txt` -> `make` -> (optional) `sudo make install`).

Additional userspace programs (Optional, but windham)

---

### Q&A:

[For a list of common Q&A, Here:](/Document/Q&A.md)

---

## Contribute:

🥰🥰 Contributions are highly welcome 🥰🥰! 

Oh, make sure that you have acknowledged [the code of conduct](CODE_OF_CONDUCT.md). 

Any questions? email me: level-128@gmx.com

---

## License and Legal issues

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
