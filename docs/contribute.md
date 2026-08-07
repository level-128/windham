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

Build with the Test profile, which configures the binary for testing and
finds the Python interpreter:

```bash
cmake -B cmake-build-test -DCMAKE_BUILD_TYPE=Test -DCFG_USE_SWAP=TRUE
cmake --build cmake-build-test
```

Run the test suite via the `check` target:

```bash
cmake --build cmake-build-test --target check
```

Or run manually:

```bash
# Full suite
sudo python3 tests/run_tests.py --binary cmake-build-test/windham_test

# Single test module
sudo python3 tests/run_tests.py --binary cmake-build-test/windham_test test_link_open

# Without root elevation (file-based operations only)
python3 tests/run_tests.py --binary cmake-build-test/windham_test --no-elevate test_probe

# List available tests
python3 tests/run_tests.py --binary cmake-build-test/windham_test --no-elevate --help
```

Tests are Python files under `tests/`. Each `def test_*()` function is a separate
test case. Tests spawn `windham_test` via `subprocess` and capture stdin/stdout/stderr.

### Test infrastructure

- `utils.py`: `create_test_device()`, `run_windham()`, `assert_success()`, `assert_error()`
- Tests requiring root automatically elevate via `pkexec`
- Loop device tests create disk files and use `losetup`
- dm-crypt tests create mapper devices and verify them in `/dev/mapper`

### Test modules

| Module | Covers |
|---|---|
| `test_creation.py` | New, Open (dry-run), wrong password |
| `test_keymgmt.py` | AddKey, DelKey, header transform, rapid add |
| `test_keymgmt_variants.py` | Anonymous keys, anonymous conversion |
| `test_aux.py` | Aux add/probe/delete |
| `test_aux_variants.py` | Aux type, no-aux flag |
| `test_link_open.py` | 5-device LINK_OPEN cascade, dangling UUID |
| `test_link_open_flags.py` | 8-device tree with SHORTCUT pruning |
| `test_shell_exec.py` | SHELL aux command execution, `@` replacement, BLCKOPEN |
| `test_decrypt.py` | Offline full-disk decryption (`--decrypt`) |
| `test_fat.py` | FatFs shell / `--create-exfat` |
| `test_suspend.py` | Suspend / Resume cycle |
| `test_params.py` | Block size, encrypt type, key file, target memory/level |
| `test_probe.py` | Probe --dir, --probe-linux, nonexistent |
| `test_backup.py` | Backup / Restore / Destroy |

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
