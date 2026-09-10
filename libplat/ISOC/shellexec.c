/* shell_exec() for ISO C platforms: system() run in a detached thread.
   ISO C threads cannot be killed and thrd_join() blocks unconditionally,
   so progress is polled through a mutex-protected flag instead: on timeout
   the thread is simply abandoned. The thread owns its own copy of the command
   string; on the success path the caller frees the arg after observing
   done, on the timeout path the thread's arg is left for it to leak.
   The lock is a file-scope object because an abandoned thread keeps using
   it; the mutex must stay valid even after arg is gone. */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WINDHAM_NO_ISOC_THREAD
#include <threads.h>
#endif

#ifdef WINDHAM_NO_ISOC_THREAD

int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out) {
   if (timed_out) *timed_out = false;
   (void) timeout_secs;
   return system(cmd);
}

#else

typedef struct {
   char *cmd;
   int   result;
   bool  done;
} ShellThreadArg;

static mtx_t     shell_result_mutex;
static once_flag shell_result_mutex_once = ONCE_FLAG_INIT;

static void shell_result_mutex_init(void) {
   mtx_init(&shell_result_mutex, mtx_plain);
}

static int shell_thread_fn(void *arg_) {
   ShellThreadArg *arg = arg_;
   int result = system(arg->cmd);
   mtx_lock(&shell_result_mutex);
   arg->result = result;
   arg->done = true;   // last touch of arg
   mtx_unlock(&shell_result_mutex);
   return 0;
}

int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out) {
   if (timed_out) *timed_out = false;

   if (timeout_secs == 0)
      return system(cmd);

   call_once(&shell_result_mutex_once, shell_result_mutex_init);

   ShellThreadArg *arg = malloc(sizeof(*arg));
   if (!arg)
      return system(cmd);
   // strdup() is POSIX, not ISO C; the thread reads cmd through its own copy
   size_t cmd_len = strlen(cmd) + 1;
   arg->cmd = malloc(cmd_len);
   if (!arg->cmd) { free(arg); return system(cmd); }
   memcpy(arg->cmd, cmd, cmd_len);
   arg->done = false;

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
      bool done;
      int  ret = 0;

      mtx_lock(&shell_result_mutex);
      done = arg->done;
      if (done)
         ret = arg->result;
      mtx_unlock(&shell_result_mutex);

      if (done) {
         free(arg->cmd);
         free(arg);
         return ret;
      }

      timespec_get(&now, TIME_UTC);
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
