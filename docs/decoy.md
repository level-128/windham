# Decoy Partition

A Decoy Partition hides an encrypted Windham partition under a visible, identifiable
partition (usually the last GPT partition or trailing free area). The visible partition
and the encrypted partition overlap on disk — the encrypted data is stored at the end
of the visible partition's space, before the GPT backup header area.

## Threat model

If someone forces you to disclose your disk content, you can point to the visible
partition and deny the existence of the encrypted one. The encrypted data has no
signature and, if the visible partition is large enough, the extra random-looking
sectors can be explained away as filesystem noise, or someone simply wiped your disk
before formatting the filesystem, which is common if you bought a used disk from
someone else.

## Creating a decoy partition

```bash
# Overwrite with random data first (critical for deniability)
sudo dd if=/dev/urandom of=/dev/sdb bs=16M

# Create a visible partition (e.g., FAT32) at the start of the disk
sudo parted /dev/sdb mklabel gpt
sudo parted /dev/sdb mkpart primary fat32 1MiB 100%

# Create the decoy partition (1 GiB at the end of the disk)
sudo windham New /dev/sdb   --decoy-size=1024
```

Windham reads the GPT layout, finds the last partition's end, and places the
decoy header just before the GPT backup area.

## How it works

1. Windham reads the GPT header at LBA 1 and the partition entry array.
2. It sorts partitions by ending LBA (descending) to find the **last** partition.
3. The decoy partition's `end_sector` is the last partition's end LBA minus the
   header area (40 sectors).
4. The decoy partition starts at `end_sector - decoy_size`, aligned to block size.
5. The header is written at `(last_partition_end + 1 - HEADER_AREA_IN_SECTOR) * 512`.

When opening a decoy partition, use `--decoy`:

```bash
sudo windham Open /dev/sdb --decoy
```

`Windham Probe` does not handle decoy partitions specially — whether a decoy
partition is detected by `Probe` depends on whether the leading sectors contain
random data or a recognizable tag.

## Limitations

### Filesystem compatibility

The visible filesystem must write data **linearly from start to end**. FAT32 and
ExFAT work well — they typically allocate from low to high sectors. EXT4 and most
journaling filesystems do NOT guarantee this and may overwrite the decoy area.

### TRIM / discard

SSD devices with TRIM support will periodically discard unused sectors. If the
decoy area is not written by the visible filesystem, the SSD may mark those sectors
as discarded, creating a visible "hole" of invalid data. This destroys plausible
deniability. Use HDDs or USB flash drives (no TRIM) for maximum security, or
create a non-TRIM mapping on top (e.g., a default-parameter LUKS or Windham
partition).

### GPT modifications

Modifying the GPT partition table (creating, resizing, or deleting partitions) after
creating the decoy partition may shift the header location or overwrite it. **Never
modify the GPT after creating a decoy partition.** If you must, back up the header
first with `Backup` and `Restore`.

### No aux zone

Decoy partitions do not support the aux zone. The aux zone is placed immediately
after the header, and in a decoy setup there may not be room between the decoy
header and the end of the visible partition.

### Single decoy per device

Only the **last** GPT partition can host a decoy partition. This is determined by
the GPT solver — it reads all partition entries, sorts by ending LBA, and uses
the last one.

## Security

- **Always overwrite the device with random data before deployment.** Without this,
  the decoy area may contain recognizable patterns (all zeros) that an attacker
  can identify.
- The decoy partition's location is deterministic from the GPT layout. An attacker
  who knows a decoy partition might exist can calculate its location. The
  plausible deniability comes from the fact that the encrypted data looks
  indistinguishable from random noise or trivially explainable.
- For maximum deniability, create the decoy partition within a normal Windham
  partition — the outer partition's header already looks random, making the
  inner decoy header blend in.
