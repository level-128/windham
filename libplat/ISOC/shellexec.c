/* shell_exec() for ISO C platforms: system() run in a detached thread.
   ISO C threads cannot be killed and thrd_join() blocks unconditionally,
   so progress is polled through an atomic flag instead: on timeout the
   thread is simply abandoned. The thread owns its own copy of the command
   string; on the success path the caller frees the arg after observing
   done, on the timeout path the thread's arg is left for it to leak. */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <threads.h>
#include <stdatomic.h>

#if defined(__STDC_NO_THREADS__) || defined(WINDHAM_NO_ISOC_THREAD)

int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out) {
   if (timed_out) *timed_out = false;
   (void) timeout_secs;
   return system(cmd);
}

#else

typedef struct {
   char *cmd;
   int   result;
   atomic_bool done;
} ShellThreadArg;

static int shell_thread_fn(void *arg_) {
   ShellThreadArg *arg = arg_;
   arg->result = system(arg->cmd);
   atomic_store(&arg->done, true);   // last touch of arg
   return 0;
}

int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out) {
   if (timed_out) *timed_out = false;

   if (timeout_secs == 0)
      return system(cmd);

   ShellThreadArg *arg = malloc(sizeof(*arg));
   if (!arg)
      return system(cmd);
   // strdup() is POSIX, not ISO C; the thread reads cmd through its own copy
   size_t cmd_len = strlen(cmd) + 1;
   arg->cmd = malloc(cmd_len);
   if (!arg->cmd) { free(arg); return system(cmd); }
   memcpy(arg->cmd, cmd, cmd_len);
   atomic_init(&arg->done, false);

   thrd_t thr;
   if (thrd_create(&thr, shell_thread_fn, arg) != thrd_success) {
      int ret = system(cmd);
      free(arg->cmd);
      free(arg);
      return ret;
   }
   thrd_detach(thr);

   struct timespec start, now;
   timespec_get(&start, TIME_UTC);
   for (;;) {
      timespec_get(&now, TIME_UTC);
      if (atomic_load(&arg->done)) {
         int ret = arg->result;
         free(arg->cmd);
         free(arg);
         return ret;
      }
      if ((now.tv_sec - start.tv_sec) >= (time_t)timeout_secs) {
         // Timeout: return failure; the abandoned thread is the sole owner
         // of arg from here on (the memory is never reclaimed).
         if (timed_out) *timed_out = true;
         return -1;
      }
      thrd_sleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100000000}, NULL);
   }
}

#endif
