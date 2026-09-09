/* shell_exec() for the browser sandbox: there is no shell. The aux exec
   feature is unreachable here (the web frontend never passes
   --aux-exec), but keep an explicit stub so that no system() call
   path ever exists in the wasm build. */

#include <stdbool.h>

int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out) {
   (void) cmd;
   (void) timeout_secs;
   if (timed_out) *timed_out = false;
   return -1;
}
