Platform-dependent code should be placed under this folder.

## Platform selection

Each root-level `.c` file dispatches to one of:

  GNU_Linux/  — Linux via `WINDHAM_PLAT_GNU_LINUX`
  ISOC/       — all other platforms (including WASI and Emscripten)

(Former WASI/ directory copies have been consolidated into ISOC/ where
implementations were identical or nearly identical.)

## ISOC compile-time toggles

### CFG_VFS_DISK_METADATA

When defined, device/file size is read from `/disk_size` (a plain-text
file on the virtual FS containing a decimal uint64) instead of using
fseek(SEEK_END).  Use this when the backing store is a flash/block device
whose size is not self-contained — for example embedded systems, or
Emscripten builds where the virtual FS placeholder is zero-length.
