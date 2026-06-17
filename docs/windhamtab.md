# /etc/windhamtab and Boot-time Unlock

Windham supports `/etc/windhamtab` — a configuration file similar to systemd's
`/etc/crypttab`. It describes encrypted devices to be unlocked at boot time.

## File format

First run creates a template:

```bash
sudo windham Open TAB
```

Format (one device per line):

```
<device> <mapper_name> <key_method> <options>
```

Examples:

```
/dev/sda                    root  ASK      readonly
UUID=abc-def-123            home  KEYFILE=/etc/keys/home.key
/dev/nvme0n1p3              data  CLEVIS=/etc/clevis/data.jwe  nofail
/dev/sdb                    swap  ASK      allow-discards,no-read-workqueue
```

### Key methods

| Method | Description |
|---|---|
| `ASK` | Prompt for password interactively |
| `KEYFILE=<path>` | Read password from a file |
| `CLEVIS=<path>` | Decrypt using Clevis (TPM, Tang, etc.) |

### Options (comma-separated)

`readonly`, `allow-discards`, `no-read-workqueue`, `no-write-workqueue`,
`nofail`, `systemd`, `no-map-partition`, `max-unlock-mem=<KiB>`,
`max-unlock-time=<sec>`

### Pass ordering

Add a `pass:<n>` entry to control unlock order:

```
<device> <name> <key> <options>,pass:1
<device> <name> <key> <options>,pass:2
```

Lower pass numbers are processed first. Use `--windhamtab-pass=<n>` to execute only
a specific pass.

---

## Clevis + TPM2 integration

### Register a random key with TPM2

```bash
sudo windham AddKey /dev/sda --generate-random-key \
  | sudo clevis encrypt tpm2 '{}' > /etc/clevis/root.jwe
```

This generates a random 32-byte key, prints it to stdout, pipes it to `clevis encrypt`
which seals it with the TPM2, and writes the JWE blob to a file.

### Unlock with Clevis at boot

In `/etc/windhamtab`:

```
/dev/sda root CLEVIS=/etc/clevis/root.jwe
```

Or from the command line:

```bash
cat /etc/clevis/root.jwe | sudo clevis decrypt tpm2 '{}' \
  | sudo windham Open /dev/sda --keystdin
```

### Clevis with Tang (network-based)

```bash
sudo windham AddKey /dev/sda --generate-random-key \
  | sudo clevis encrypt tang '{"url":"http://tang-server"}' > /etc/clevis/root.jwe
```

---

## Systemd integration

When running as a systemd service, the password prompt is not available on the
terminal. Use `systemd` as an option in windhamtab:

```
/dev/sda root ASK systemd
```

Windham uses `systemd-ask-password` for interactive prompts when `systemd` is
specified. This integrates with plymouth (graphical boot splash).

---

## Boot-time unlock with init daemon

Create an init service that runs before `local-fs.target`:

```ini
# /etc/systemd/system/windham-open.service
[Unit]
Description=Windham device unlock
DefaultDependencies=no
Before=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/windham Open TAB
RemainAfterExit=yes

[Install]
WantedBy=local-fs.target
```

Then `systemctl enable windham-open.service`.
