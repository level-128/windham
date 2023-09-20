# Windham

Windham is free and open-source software for disk encryption, based on the Linux dm-crypt module. It features a header 
which is indistinguishable from cryptographically secure pseudo-random data, and also supports creating a Decoy
Partition

**_!!!! This software is in an unstable stage. Use it only for evaluation purposes. !!!!_**

## How To install?
You can Choose to:
- Download the binaries for X86_64 (Intel Haswell / AMD Bulldozer GEN4, aka AMD Excavator Family 15h, 
or later.) under `build` folder. **The binary is not meant for release, use it only for evaluation purposes.**
- Compile by your own. __Note: Untested on architectures other than X86_64, Argon2_bench is only available for X86_64__. 

To compile, `libdevmapper.h` and the device-mapper subsystem is required. Install `libdevmapper-dev` on Debian-based 
distro; or `device-mapper-devel` on Fedora-based distro.


## Basic steps:
1. First, grab the device that you want to encrypt. find your device location under `/dev`, you can do this by using 
your disk manager or using command `lsblk`. It might be something like `/dev/sdb` or `/dev/nvme0n1`, or `/dev/sdb2` if 
you prefer to create an encrypted partition instead.
2. To create a new Windham device, use command `Windham New *your device*`. For example, creating a Windham device on
`/dev/sdb`, use command `sudo windham New /dev/sdb` and enter your key-phrase. 
3. To map your device, use command `windham Open *your device* --map-to=*name*`. For example, to decrypt `/dev/sdb`,
using `sudo windham Open /dev/sdb --map-to=enc1` will create a mapper device at `/dev/mapper/enc1`.
4. create filesystem on `/dev/mapper/enc1` as you wish.
5. To close your device, use `windham close *name*`. 

&nbsp;

[Want to know how Windham works? Here:](/Document/technical_details.md)

## Introduction to Decoy Partition

### What is Decoy Partition?

A Decoy Partition is a FAT32 partition located at the same area with the encrypted Windham partition. The encrypted
partition occupies the unused sector of the FAT32 partition. In a case where the user needs to deny the existence of the
encrypted partition, which the cryptographically random header doesn't constitute a strong rebuttal of its existence, 
Decoy Partition could be used. 

### How to enable Decoy Partition?

Use `windham New *your device* --decoy` to create a decoy partition along with the encrypted partition. To Open an
encrypted partition which contains a Decoy Partition, open as if you were opening a partition without it. If you have
deleted the decoy partition, auto-detection will not work. In this case, use argument `--decoy` (Except for `New` and
`Close`) to force the program to recognize the given device has a Decoy Partition.

### Note for using Decoy Partition
There is no protection to ensure the modification of the decoy partition will not overwrite the encrypted partition. In 
a case that a large amount of file needs to be deleted, reformatting the filesystem is a better idea. 


## Quick Q&A

- My system cannot identify the encrypted partition before decrypting. What's going on?
  - Windham is designed to not leave any pre-defined pattern or statical trace to identify its existence. The only
way to identify it is to provide a correct key to the correct slot. It is by-design that Windham is undetectable.

&nbsp;

- What is the Master Key?
  - The Master Key is a unique key per device which would grant the holder full access to the encrypted drive. if your 
master key is compromised, Anyone with a master key can unlock your device. In this case, use `windham New *device*` 
with a random key to overwrite the original header. ALL DATA WILL BE LOST! overwrite the header multiple times is
recommended.

&nbsp;

- I'm sure that I provided the correct key-phrase. But I have received an error message: 
`Cannot unlock the target because time or memory limit has reached. This is probably because a wrong key
has been provided, or your compute resources may be too insufficient to unlock the target created
by a faster computer....`
  -  If you try to unlock a drive created by a faster
computer, the parameter that suits for a fast computer may be beyond the limit by your device. To continue, you can use
argument `--max-unlock-memory` (in KiB) or `--max-unlock-time` to expand the estimated compute resource allowance. If 
it's still not possible to decrypt, use `windham Open *device* --dry-run` to Open a device without mapping it. In this
case, the master key will be printed to the console. Then use `windham Open *device* --master-key=*your master key*` 
to map the device on another computer. Why is windham so strangely designed? You can read this if you're interested: 

To defend against brute force attacks, as well as the future attacks with transcended compute devices from the far
future, when adding a key-phrase, the computer which performs such action will first be benchmarked, then generate
parameters dynamically to perform as many key derivation operations as possible; such auto-adaption algorithm will
ensure the encryption method will not be weakened in future era. Also, such parameters could not be embedded in the
header in any way because of ensuring traceless; when a key-phrase is provided, the value from incremental blocks will be
computed from the last KDF iteration via one-time pad for a new parameter, which tells what memory usage and CPU time
will be used for the next step and scales the parameters by a power of the number of iterations of the Euler's number.
This way the metadata on the hard disk is randomized. But if a wrong pass-phrase has been provided, then the parameters
will be wrong during each iteration, and the program will always be asked to keep calculating using larger and larger
parameters.

&nbsp;

- `WARNING: using swap space for Key derivation function. This is potentially insecure because unencrypted swap space 
may provide hints to the master key.` What does this mean?
  - Your operating system may move parts of the data from the memory to your disk. The way that key derivation function
works, in this case, it to utilize large memory chunk to prevent brute-force attack from specially crafted hardware.
If someone could read this memory, it will provide very useful hints to your master key. You can ignore this message if 
your swap space is encrypted.

&nbsp;

- What is a key-file?
  - Key-file is a key stored in a file; it uses the full content of the file as the key. To use Key-file as the key, use
argument `--key-file=`.

---

## License and Legal issues

Copyright (C) 2023- W. Wang (level-128)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. 

This program has granted "Additional permissions" applied from article (7) when using, propagating and conveying the 
unmodified covered work. For details, see file `license.md`.

### U.S. Encryption Export Regulations

Windham is classified under ECCN 5D002 that provides or performs “non-standard cryptography” as defined in part 772 
of the EAR, and is subject to Export Administration Regulation jurisdiction from the Bureau of Industry and Security.
A notification to BIS and the ENC Encryption Request Coordinator via email of the internet location (e.g., URL or internet
address) of the source code is required when the cryptographic functionality of the source code is updated or modified.
This can be done by notifying level-128 (Email: <level-128@gmx.com>) when making contributions or forking the software.

I know this is not ideal... 
