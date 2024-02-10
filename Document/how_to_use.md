# Advanced features and examples:

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