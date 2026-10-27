# Contributing

## Developer setup

```bash
git clone https://github.com/level-128/windham.git
cd windham
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DCFG_USE_SWAP=1
cmake --build cmake-build-debug
```

The Debug build:
- Allows debugger attachment (`WINDHAM_NO_DISABLE_ATTACH`)
- Disables speculation mitigation (`WINDHAM_NO_ENFORCE_SPEC_MITIGATION`)
- Enables swap for testing convenience (`CFG_USE_SWAP`)

## Running tests

The suite is split into two blocks by target platform:

- **ISO C baseline** (`REQUIRES = "isoc"`, or `"any"`): runs against a directly
  compiled ISO C binary. Pure userspace — regular files, no root, no kernel
  device-mapper. This is the block that must pass everywhere.
- **GNU/Linux backend** (`REQUIRES = "gnu-linux"`): exercises the kernel
  dm-crypt backend (loop devices, `/dev/mapper`, cascade unlock). Requires
  root and a CMake build.

The runner auto-detects the platform from the binary (override with
`--platform=isoc|gnu-linux`) and skips tests whose `REQUIRES` does not match.

### ISO C baseline block

Compile `frontend.c` directly (no build system), then pass the binary path:

```bash
cc -std=c11 -O2 frontend.c -lm -o windham_isoc

# Full ISOC suite — no root needed
python3 tests/run_tests.py --binary ./windham_isoc

# Single test module
python3 tests/run_tests.py --binary ./windham_isoc test_aux
```

Real `Open`s in platform-neutral tests pass `--print-encryption` (the no-op
print driver) so they behave identically without a kernel mapper.

### GNU/Linux backend block

Build with the Test profile, which configures the binary for testing and
finds the Python interpreter:

```bash
cmake -B cmake-build-test -DCMAKE_BUILD_TYPE=Test -DCFG_USE_SWAP=TRUE
cmake --build cmake-build-test
```

Run the suite via the `check` target, or manually:

```bash
cmake --build cmake-build-test --target check

# Full suite (elevates via pkexec automatically)
python3 tests/run_tests.py --binary cmake-build-test/windham_test

# Single test module
python3 tests/run_tests.py --binary cmake-build-test/windham_test test_link_open

# Without root elevation (file-based operations only)
python3 tests/run_tests.py --binary cmake-build-test/windham_test --no-elevate test_probe

# List available tests
python3 tests/run_tests.py --binary cmake-build-test/windham_test --no-elevate --help
```

Tests are Python files under `tests/`. Each `def test_*()` function is a separate
test case. Tests spawn the binary via `subprocess` and capture stdin/stdout/stderr.

### Test infrastructure

- `utils.py`: `create_test_device()`, `run_windham()`, `assert_success()`, `assert_error()`
- Platform gating: module-level `REQUIRES` attribute gates a whole file; a
  function attribute (`test_x.requires = "gnu-linux"`) gates a single test;
  `"any"` runs on both blocks
- Root elevation via `pkexec` is attempted only for the `gnu-linux` block
- Loop device tests create disk files and use `losetup`
- dm-crypt tests create mapper devices and verify them in `/dev/mapper`

### Test modules

| Module | Block | Covers |
|---|---|---|
| `test_creation.py` | any | New, Open (dry-run), wrong password |
| `test_keymgmt.py` | any | AddKey, DelKey, header transform, rapid add |
| `test_keymgmt_variants.py` | any | Anonymous keys, anonymous conversion |
| `test_aux.py` | any | Aux add/probe/delete; `--aux-probe --aux-exec`; public entries via `--master-key`; DelKey aux cleanup; LINK_OPEN entry lifecycle; `--aux-rm` |
| `test_aux_variants.py` | any | Aux type, no-aux flag |
| `test_shell_exec.py` | any + one gnu-linux test | SHELL execution opt-in (`--aux-exec`), BLCKOPEN, single-device `@` replacement; cascade `@` replacement (gnu-linux only) |
| `test_suspend.py` | any | Suspend / Resume cycle |
| `test_params.py` | any | Block size, encrypt type, key file, target memory/level; `Bench`; `--show-master-key`; negative opens (nonexistent, `UUID=` prefix); Close of unmapped name |
| `test_probe.py` | any | Probe --dir, --probe-linux, nonexistent |
| `test_backup.py` | any | Backup / Destroy; Backup→Destroy→Restore roundtrip with aux survival; fold backup/restore roundtrip; QR backup (terminal + BMP) |
| `test_decrypt.py` | any + one gnu-linux test | Userspace decrypt roundtrip (`--create-exfat` → `--decrypt` → exFAT signature); dm-crypt write-path e2e (gnu-linux only) |
| `test_fat.py` | any + one gnu-linux test | ff driver FatFs shell on Open (stdin); dm-crypt mapper superblock check (gnu-linux only) |
| `test_link_open.py` | gnu-linux | 5-device LINK_OPEN cascade, dangling UUID |
| `test_link_open_flags.py` | gnu-linux | 8-device tree with SHORTCUT pruning |

## Code structure

```
windham/
├── windham_config.h     # Build configuration (defaults + feature switches)
├── main.c              # CLI parsing, action dispatch
├── frontend.c          # main(), platform init
├── backend/            # Action implementations
│   ├── bklibopen.c     # Open + LINK_OPEN cascade
│   ├── bklibcreat.c    # New
│   ├── bklibkey.c      # AddKey, DelKey
│   ├── bklibact.c      # Suspend, Resume, Destroy, Backup, Restore
│   ├── bklibaux.c      # Aux zone add/del/probe/link
│   ├── bklibprobe.c    # Probe
│   └── bklibhelp.c     # Help text
├── libsrc/             # Core logic
│   ├── enclib.c        # Encryption, KDF, key derivation
│   ├── auxlib.c        # Aux zone data structures, serialization
│   ├── libkdf.c        # Argon2id wrapper, memory bounds
│   ├── chkhead.c       # Header entropy detection
│   ├── probelib.c      # Probe single device
│   └── srclib.c        # Shared utilities, macros
├── libplat/            # Platform-specific implementations
│   ├── GNU_Linux/      # Full support: dm-crypt, keyring, loop ioctl
│   ├── ISOC/           # ISO C11 portable mode
│   └── WASI/           # Emscripten / WebAssembly
├── driver/             # Driver registry + dm-mapper / FatFs shell / decrypt
├── library/            # Third-party libraries
├── include/            # Headers: windham_const.h, argon2.h, sha256.h, etc.
├── web/                # Emscripten web app (index.html, worker.js)
└── tests/              # Python test suite
```

## Commit style

```
feat: description          # New feature
fix: description           # Bug fix
docs: description          # Documentation only
refactor: description      # Code restructuring
test: description          # Test changes
```

## Building the documentation

```bash
# No build step needed — docs/ is plain Markdown.
# Preview: open in any Markdown viewer or GitHub.
```
