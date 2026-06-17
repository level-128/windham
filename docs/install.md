# Installation & Building

## Full support (GNU/Linux)

### Dependencies

| Package | Debian/Ubuntu | Fedora/RHEL | Arch |
|---|---|---|---|
| Device mapper | `libdevmapper-dev` | `device-mapper-devel` | `device-mapper` |
| Kernel headers | `linux-headers-$(uname -r)` | `kernel-devel` | `linux-headers` |
| Gettext | `libgettextpo-dev` | `gettext-runtime` | `gettext` |
| libblkid | `libblkid-dev` | `libblkid-devel` | `util-linux` |
| keyutils (optional) | `libkeyutils-dev` | `keyutils-libs-devel` | `keyutils` |

Optional runtime tools: `clevis`, `partx`.

### Build

```bash
git clone https://github.com/level-128/windham.git --depth=1
cd windham
cmake -B build
cmake --build build
# Binary: build/windham
```

Debug build (allows debugger attachment, more verbose):

```bash
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DCFG_USE_SWAP=1
cmake --build cmake-build-debug
```

### Feature switches

Pass with `-D<flag>=TRUE` to `cmake`:

| Flag | Effect |
|---|---|
| `CFG_NO_MODULE_KEYRING` | Disable kernel key retention service |
| `CFG_WINDHAM_ALLOW_ATTACH` | Allow debugger to attach |
| `CFG_NO_ENFORCE_SPEC_MITIGATION` | Skip Spectre mitigation |
| `CFG_NO_OPT` | Disable x86-64 SIMD optimization |
| `CFG_USE_SWAP` | Allow KDF memory to use swap space (⚠ insecure) |
| `CFG_WIPE_MEMORY` | Wipe memory after KDF |

---

## Cross-compilation

Windham supports cross-compilation for other architectures:

```bash
# Cross-compile for ARM64 from x86-64
cmake -B build \
    -D CMAKE_SYSTEM_NAME=Linux \
    -D CMAKE_SYSTEM_PROCESSOR=aarch64 \
    -D CMAKE_C_COMPILER=aarch64-linux-gnu-gcc
cmake --build build
```

When cross-compiling, `try_run` cannot execute — Windham assumes features compile
correctly. Use the feature switches above to explicitly enable/disable features.

---

## ISO C11 (basic mode)

ISO C mode compiles `frontend.c` directly. No build system is required — invoke
any C11 compiler:

```bash
cc -std=c11 -DWINDHAM_ISOC frontend.c -o windham
```

### Basic mode requirements

- 8-bit byte, 2's complement integer representation
- ASCII-compatible character set
- `stdlib.h`, `string.h`, `stdio.h` fully implemented
- ~492 KB heap (464 KB continuous)
- Stack: ~52 KB + 2× FILENAME_MAX on 64-bit (slightly less on 32-bit)


### Feature limitations vs full mode

| Feature | Full mode (GNU/Linux) | Basic mode (ISO C11) |
|---|---|---|
| dm-crypt mount/operate | ✓ | ✗ |
| Run as PID 1 | ✓ | ✗ |
| `/etc/windhamtab` | ✓ | ✗ |
| Probe `/proc/partitions` | ✓ | ✗ |
| Device UUID resolution | ✓ | ✗ |
| Kernel keyring | ✓ | ✗ |
| Header create/read/write | ✓ | ✓ |
| AddKey / DelKey | ✓ | ✓ |
| Suspend / Resume | ✓ | ✓ |
| Backup / Restore / Destroy | ✓ | ✓ |
| Master key extraction | ✓ | ✓ |
| Argon2 KDF | ✓ | ✓ (slower if no threads) |
| Unicode password input | ✓ | depends on compiler |
| Aux zone read/write | ✓ | ✓ |
| LINK_OPEN cascade | ✓ | ✗ (no dm-crypt, no UUID scan) |
| Probe single file | ✓ | ✓ |
| gettext i18n | ✓ | ✗ |

### Recommended platform features

ISO C mode works on any standards-conforming C11 environment, but several optional
host features significantly affect capabilities and security:

#### Threads (`threads.h`)

| `__STDC_NO_THREADS__` | Behavior |
|---|---|
| **Not defined** (threads available) | Parallel KDF runs two keypool zones concurrently (≈2× faster unlock). Thread-local RNG state for entropy. |
| **Defined** (no threads) | Single-threaded KDF. Shared global RNG state. Fully functional, just slower. |

The KDF loop probes both keypool zone 0 and zone 1. With threads, they run in
parallel; without, they run sequentially. For devices with few registered
passphrases, the difference is minor.

#### Unicode (`__STDC_UTF_32__`)

| `__STDC_UTF_32__` | Behavior |
|---|---|
| **Defined** | `c32rtomb` / `mbrtoc32` used for char32_t ↔ multibyte conversion. Full Unicode passwords and aux entry content supported. |
| **Not defined** | All char32_t conversions fall back to ASCII-only. Non-ASCII password characters are rejected. Aux entries with non-ASCII content produce a runtime error. **This is the case for CompCert and some embedded C compilers even when targeting Linux.** |

On Linux with glibc, `c32rtomb` / `mbrtoc32` work correctly even without
`__STDC_UTF_32__` — the macro reflects the compiler's guarantee, not the libc's
capability. On non-glibc platforms (musl, newlib, bare-metal libc), Unicode
support depends on the specific C library implementation.

#### UNIX random device files

ISO C mode probes for three UNIX device files at startup:

| Device | Purpose | If missing |
|---|---|---|
| `/dev/null` | Write-sink validation | Falls through to next check |
| `/dev/zero` | Zero-source validation | Falls through to next check |
| `/dev/random` | Entropy source for RNG | **Fallback: SHA256-DRBG + interactive user input** |

**Detection flow** (`libplat/ISOC/get_entropy.c`):

1. Verify `/dev/null` and `/dev/zero` exist by writing test patterns and reading
   back. If BOTH pass → assume UNIX-like environment.
2. In UNIX-like mode: read `/dev/random` for the initial 32-byte seed. If read
   fails → fall back to interactive mode.
3. If `/dev/null` or `/dev/zero` are absent → **pure ISO C mode**:
   - Prompts user for interactive keyboard input ("input anything as entropy")
   - Mixes `timespec_get(TIME_UTC)` timestamps with user input via SHA-256
   - Uses a SHA256-based deterministic random bit generator (DRBG) with:
     - Internal counter and per-thread state
     - Periodic re-seeding from `timespec_get` (every 32 generate calls)
     - Thread-local buffers in multi-threaded builds
   - Issues a warning if the timer resolution exceeds 1 ms

**Security implications of pure ISO C RNG**:

- The DRBG is deterministic — given the same seed, it produces the same output.
  The seed comes from user input + timestamps, which may have limited entropy.
- **Create devices only on systems with `/dev/random` or equivalent** for
  production use. Pure ISO C RNG is suitable for testing and validation, but
  the generated master keys and header random data may be predictable if the
  interactive seed is weak.
- The timer is mixed into the DRBG periodically, but without a hardware entropy
  source, the cryptographic quality depends entirely on the initial seed.
