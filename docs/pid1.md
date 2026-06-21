# Running as PID 1 (Embedded / Early Userspace)

Windham can operate as the init process (PID 1) for embedded Linux systems or
early userspace environments where a separate init daemon is not available.

> **Do not use this on a full Linux distribution.** This is for embedded systems,
> initramfs with no init daemon, or very minimal environments.

## Behavior as PID 1

Windham detects it is PID 1 at startup and:
1. Ignores the command-line arguments.
2. Reads a pre-compiled command from the `.windhaminit` section.
3. Executes the command.
4. On success, `exec`s into the fallback program (default: `/bin/sh`).
5. On failure, the kernel panics: `Kernel panic - not syncing - Attempted to kill init!`
   (or, if `--nofail` is set, proceeds to `exec` the fallback anyway).

## Pre-compiled command format

The default pre-compiled command is `windham Open TAB` followed by `exec /bin/sh`.

To modify it, edit the `.windhaminit` section in the binary with a hex editor:

```
WINDHAMINIT:\xff<program>\xff<Action>\xff<argument>\xff<option>...
```

- Elements separated by `\xff` (0xFF byte)
- Strings terminated by `\x00` (null byte)
- Each string: max 255 characters
- All messages are printed to kernel `dmesg`

```bash
# Find the section
objdump -h windham | grep windhaminit

# Example output:
#   16 .windhaminit  00000100  00000000000416e0  00000000000416e0  000416e0  2**5
# The address (000416e0) is where the section begins in the file.

# Edit with hexedit
hexedit /path/to/windham
#   Enter → type 0x416e0 → Enter (jump to address)
#   Tab to toggle between ASCII and hex views
#   F2 to save, Ctrl+C to exit
```

```
000416E0   57 49 4E 44  48 41 4D 49  4E 49 54 3A  WINDHAMINIT:
000416EC   FF 2F 62 69  6E 2F 73 68  FF 4F 70 65  ./bin/sh.Ope
000416F8   6E FF 54 41  42 00 00 00  00 00 00 00  n.TAB.......
00041704   00 00 00 00  00 00 00 00  00 00 00 00  ............
00041710   00 00 00 00  00 00 00 00  00 00 00 00  ............
```

### Example: single device unlock

```
WINDHAMINIT:\xff/bin/sh\xffOpen\xff/dev/sda\xff--key-file=/boot/key.bin\xff--nofail\x00
```

### Example: unlock then exec bash

```
WINDHAMINIT:\xff/bin/bash\xffOpen\xffTAB\xff--nofail\x00
```

## Kernel command line

```
init=/path/to/windham
```

Windham becomes PID 1, executes its pre-compiled command, then `exec`s the
fallback program.

## Limitations

- No interactive input (no TTY in early userspace, unless systemd-ask-password is available)
- Use key files (`--key-file`) or Clevis for non-interactive unlock
- `dmesg` is the only output channel
