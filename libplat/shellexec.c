#ifndef INCL_PLAT_SHELLEXEC
#define INCL_PLAT_SHELLEXEC

#include <stdint.h>
#include <stdbool.h>

/* Run <cmd> through the system shell.
   - timeout_secs == 0: wait indefinitely.
   - timeout_secs > 0:  terminate the command when it exceeds the timeout
                        (SIGKILL where the platform allows it) and set
                        *timed_out (if non-NULL) to true.
   Returns the command's exit status (0 == success), -1 on launch failure.
   The implementation never references <cmd> after returning, so the caller
   may always free it. */
int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out);

#if defined(WINDHAM_PLAT_EMSCRIPTEN)
#include "WASI/shellexec.c"
#elif defined(WINDHAM_PLAT_GNU_LINUX)
#include "GNU_Linux/shellexec.c"
#else
#include "ISOC/shellexec.c"
#endif

#endif
