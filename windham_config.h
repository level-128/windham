/*
 * windham_config.h — Windham build configuration.
 *
 * This header is the single source of truth for every build-time switch.
 * frontend.c and main.c include it FIRST, before any other source file.
 *
 * Default state: nothing is enabled — the pure ISO C11 baseline, exactly
 * what a direct `cc -std=c11 frontend.c -lm` build compiles.
 *
 * Precedence: value defaults below are guarded with #ifndef so that
 * definitions passed by the build system (cmake -D..., compiler -D)
 * always take precedence. The GNU/Linux and Emscripten builds enable
 * their feature sets from their respective CMakeLists.txt; this file
 * only supplies the defaults and the documentation.
 */

#ifndef WINDHAM_CONFIG_H
#define WINDHAM_CONFIG_H


/* ============================================================================
 * Platform selection
 * ============================================================================
 * No platform macro defined = ISO C11 baseline (any conforming C11
 * compiler, no Linux headers). The build system selects the platform;
 * uncomment one manually only for non-CMake builds.
 */

// #define WINDHAM_PLAT_GNU_LINUX
// Full GNU/Linux support: dm-crypt mapping, kernel key retention service,
// /proc/partitions probe, seccomp filter, /etc/windhamtab, shebang entry.
// Requires Linux kernel headers. The libraries are supplied by CMake;
// building this platform by direct cc is not supported (see
// library/include_all_libs.c).
//
// #define WINDHAM_PLAT_EMSCRIPTEN
// Emscripten / WebAssembly build: read-only FatFs shell in the browser.
// See web/CMakeLists.txt.


/* ============================================================================
 * Values with defaults
 * ============================================================================
 * These are actual defaults; the build system may override each one with
 * a -D definition. Names matching the CMake cache variables
 * (CFG_DEFAULT_TARGET_TIME, ...) are forwarded by CMake as the plain
 * DEFAULT_* / WINDHAMTAB_FILE definition below.
 */

#ifndef DEFAULT_TARGET_TIME
#define DEFAULT_TARGET_TIME 1.5
/* Target key derivation time, in seconds. KDF parameters (Argon2id
   m_cost / t_cost) are tuned so derivation takes about this long. */
#endif

#ifndef MAX_UNLOCK_TIME_FACTOR
#define MAX_UNLOCK_TIME_FACTOR 5
/* Hard cap for unlock time: max unlock time = DEFAULT_TARGET_TIME ×
   this factor. Guards against pathological KDF parameter combinations. */
#endif

#ifndef DEFAULT_BLOCK_SIZE
#define DEFAULT_BLOCK_SIZE 4096
/* Default encryption sector size, in bytes. */
#endif

#ifndef DEFAULT_DISK_ENC_MODE
#define DEFAULT_DISK_ENC_MODE "aes-xts-plain64"
/* Default cipher-chainmode-ivmode for newly created devices. */
#endif

#ifndef DEFAULT_DISK_ENC_MEM_RATIO_CAP
#define DEFAULT_DISK_ENC_MEM_RATIO_CAP 30
/* Memory cap ratio (percent of total RAM) for the disk-encryption KDF. */
#endif

#ifndef DEFAULT_DISK_KEY_SIZE_BYTES
#define DEFAULT_DISK_KEY_SIZE_BYTES 64
/* Default disk key size, in bytes: AES-256-XTS = 32 data + 32 tweak.
   On-disk format constant; do not change. */
#endif

#ifndef DEFAULT_AUX_SECTOR_SIZE
#define DEFAULT_AUX_SECTOR_SIZE 16
/* Auxiliary zone size for new devices, in 512-byte sectors.
   On-disk format constant; do not change. */
#endif

#ifndef DEFAULT_MIN_MEMLOCK_SIZE
#define DEFAULT_MIN_MEMLOCK_SIZE (8 * 1024 * 1024)
/* Minimum memory to mlock() for KDF buffers, in bytes (8 MiB). */
#endif

#ifndef WINDHAMTAB_FILE
#define WINDHAMTAB_FILE "/etc/windhamtab"
/* Path of the windhamtab configuration file (GNU/Linux only). */
#endif

#ifndef CFG_DEFAULT_DRIVER
#define CFG_DEFAULT_DRIVER "ff"
/* Default action driver: "ff" (FatFs shell) in the ISO C baseline.
   The GNU/Linux CMake build overrides this to "dm-mapper". */
#endif

#ifndef CFG_ISOC_HEADERIO_CACHE_SIZE
#define CFG_ISOC_HEADERIO_CACHE_SIZE (1024 * 512)
/* Total bytes of read cache for the ISO C header I/O layer, split
   across CACHE_LINE_CNT lines (libplat/ISOC/headerio.c). */
#endif


/* ============================================================================
 * Feature switches — nothing is enabled by default
 * ============================================================================
 * Uncomment a switch to enable it. The CMake build system passes the same
 * definitions as -D when the corresponding CMake option is ON.
 */

/* ---- Security hardening ---- */

// #define CFG_USE_SWAP
// Allow KDF memory to use swap space. Insecure: key material may be paged
// out to disk. OFF by default; turning it on while memory wiping is off
// exposes keys to swap.

// #define CFG_WIPE_MEMORY
// Wipe Argon2 internal memory after key derivation (sets
// ARGON2_CLEAR_INTERNAL_MEMORY=1). Slightly slower; keeps derived key
// material from lingering in RAM.

// #define CFG_NO_MODULE_KEYRING
// Disable the Linux kernel key retention service (keyctl / keyutils).
// Windham then keeps keys in process memory instead.

// #define WINDHAM_NO_SECCOMP
// Disable the seccomp filter. While disabled, the system is treated as
// untrusted and auxiliary shell commands are refused.

// #define WINDHAM_NO_DISABLE_ATTACH
// Allow a debugger to attach under Release builds. Normally the Release
// build refuses to run when a tracer is detected. CMake sets this
// automatically for Debug/Test builds and cross builds.

// #define WINDHAM_NO_ENFORCE_SPEC_MITIGATION
// Skip enforcing Spectre mitigation at startup. CMake auto-detects this
// when it cannot verify mitigation support; non-GNU/Linux builds define it.

/* ---- Drivers ---- */

// #define CFG_DRIVER_NO_DMMAPPER
// Disable the dm-mapper driver (dm-crypt mapping, GNU/Linux). The
// Emscripten build defines this.

// #define CFG_DRIVER_NO_FF
// Disable the FatFs driver: the interactive shell (ISO C) and the
// --create-exfat / --diskfile format helpers.

// #define CFG_NO_FF_CREATE
// Disable exFAT creation (--create-exfat). Requires the FatFs driver
// (see dependency checks below).

// #define CFG_DRIVER_NO_DECRYPT
// Disable the offline full-disk decryption driver (--decrypt,
// --print-encryption, --to=<file>).

/* ---- Shell / filesystem behavior ---- */

// #define CFG_FF_SHELL_NOINTERACTIVE
// Disable the interactive FatFs shell; read commands from ./cmd_queue
// instead. Used by the Emscripten build.

// #define CFG_VFS_DISK_METADATA
// Use ./disk_size as the disk metadata instead of probing the backing
// file size. Used by the Emscripten build.

// #define CFG_TARGET_READONLY
// Keep only actions that do not require writing to the target device
// (create/format/AddKey/DelKey etc. are compiled out).

/* ---- Build size / portability ---- */

// #define CFG_NO_TEXT
// Strip all help texts for a minimal binary size.

// #define CFG_NO_ENTROPY_DETECTION
// Disable the huffman-based entropy detection used to pick smart KDF
// parameters. The huffman library is then not compiled in.

// #define CFG_ASCII
// Force ASCII-only mode: mask UTF-16/UTF-32 Unicode support (passwords
// and aux entries fall back to ASCII).

// #define CFG_NO_OPT
// Disable the x86-64 SIMD optimization in Argon2 (portable "ref"
// implementation is used). Maps to __Argon2_opt_disable__; CMake also
// selects the reference source files.

// #define CFG_ISOC_HEADERIO_ENABLE_CACHE
// Enable the read cache in the ISO C header I/O layer. Useful only when
// libc has no buffering (bare-metal / web). The Emscripten build enables it.

// #define WINDHAM_NO_ISOC_THREAD
// Disable multithreading (threads.h). Unlocking runs up to 2× slower.
// Maps to ARGON2_NO_THREADS. CMake auto-disables it when the platform
// lacks working ISO C threads.

// #define WINDHAM_NO_SHEBANG_ENTRY
// Disable the shebang entry point ("#!/bin/windham <device> ...").
// CMake auto-detects this when getauxval(AT_EXECFN) is unavailable.

// #define WINDHAM_HAS_MNTENT
// Let Probe show mount info via mntent.h (glibc only). CMake
// auto-detects this; musl / uClibc do not provide mntent.h.

// #define WINDHAM_NO_LOOP_IOCTL
// Fall back to the losetup command instead of loop device ioctls
// (LOOP_CONFIGURE, LOOP_CTL_GET_FREE, ...). CMake auto-detects this
// when <linux/loop.h> is incomplete.

// #define WINDHAM_REPRODUCIBLE_BUILD
// Replace the build timestamp and kernel version with fixed strings so
// the executable is byte-for-byte reproducible.

/* ---- KDF tuning ---- */

// #define CFG_32BIT_ADDR_SPACE 22
// Override the Argon2 memory limit: max m_cost = 2^N KiB
// (21 = 2 GiB, 22 = 4 GiB, 31 = 2 TiB). Maps to ARGON2_MAX_MEMORY_BITS.
// Undefined = auto-detect from the pointer width (argon2.h).

// #define WINDHAM_SPEC_MITIGATION 2
// Compile-time statement about the target system's Spectre mitigation
// (0 = mitigated, 2 = not needed). CMake detects this at configure time;
// setting 2 silences the startup delay warning on affected systems.


/* ============================================================================
 * Derived macros
 * ============================================================================
 * Do not edit these directly — control them through the switches above.
 */

#ifdef CFG_WIPE_MEMORY
# ifndef ARGON2_CLEAR_INTERNAL_MEMORY
#  define ARGON2_CLEAR_INTERNAL_MEMORY 1
# endif
#else
# ifndef ARGON2_CLEAR_INTERNAL_MEMORY
#  define ARGON2_CLEAR_INTERNAL_MEMORY 0
# endif
#endif

#ifdef CFG_32BIT_ADDR_SPACE
# ifndef ARGON2_MAX_MEMORY_BITS
#  define ARGON2_MAX_MEMORY_BITS CFG_32BIT_ADDR_SPACE
# endif
#endif

#ifdef CFG_NO_OPT
# ifndef __Argon2_opt_disable__
#  define __Argon2_opt_disable__
# endif
#endif

#if defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)
# ifndef ARGON2_NO_THREADS
#  define ARGON2_NO_THREADS
# endif
#endif


/* ============================================================================
 * Dependency validation
 * ============================================================================
 */

#if defined(CFG_NO_FF_CREATE) && defined(CFG_DRIVER_NO_FF)
#error "CFG_NO_FF_CREATE (exFAT creation) requires the FatFs driver. Remove CFG_DRIVER_NO_FF or CFG_NO_FF_CREATE."
#endif

#if defined(CFG_FF_SHELL_NOINTERACTIVE) && defined(CFG_DRIVER_NO_FF)
#error "CFG_FF_SHELL_NOINTERACTIVE (cmd_queue shell) requires the FatFs driver. Remove CFG_DRIVER_NO_FF."
#endif

#if defined(WINDHAM_PLAT_GNU_LINUX) && defined(WINDHAM_PLAT_EMSCRIPTEN)
#error "WINDHAM_PLAT_GNU_LINUX and WINDHAM_PLAT_EMSCRIPTEN are mutually exclusive. Enable exactly one platform."
#endif

#endif /* WINDHAM_CONFIG_H */
