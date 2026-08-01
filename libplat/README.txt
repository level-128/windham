Platform-dependent code should be placed under this folder.

## Platform selection

Each root-level `.c` file dispatches to one of:

  GNU_Linux/  -- Linux via `WINDHAM_PLAT_GNU_LINUX`
  ISOC/       -- all other platforms (including Emscripten)
  WASI/       -- some unique diff for Emscripten