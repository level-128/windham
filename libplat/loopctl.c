#ifndef INCL_LOOPCTL
#define INCL_LOOPCTL

void init_device(
   const char * filename,
   bool         is_map_block,
   bool         is_readonly,
   bool         is_nofail,
   bool         is_bypass_fs_check,
   uintmax_t    disk_file_size,
   uintmax_t    block_size);

void create_file(const char *path, size_t size);

void fin_device(void);

#if defined(WINDHAM_PLAT_GNU_LINUX)
#include "GNU_Linux/loopctl.c"
#else
#include "ISOC/loopctl.c" /* WASI + Emscripten + fallback */
#endif

#endif