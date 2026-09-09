/* shell_exec() for GNU/Linux: fork + execve. Unlike an in-process system()
   thread, a real child process can be SIGKILLed on timeout. The seccomp
   filter and no_new_privs installed by the parent are inherited. */

#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <threads.h>

extern char **environ;

int shell_exec(const char *cmd, unsigned timeout_secs, bool *timed_out) {
   if (timed_out) *timed_out = false;

   pid_t pid = fork();
   if (pid < 0) {
      perror("fork");
      return -1;
   }

   if (pid == 0) {
      char *const argv[] = { (char *)"sh", (char *)"-c", (char *)cmd, NULL };
      execve("/bin/sh", argv, environ);
      _exit(127);
   }

   int status = 0;
   if (timeout_secs == 0) {
      if (waitpid(pid, &status, 0) < 0)
         return -1;
      return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
   }

   struct timespec start, now;
   timespec_get(&start, TIME_UTC);
   for (;;) {
      if (waitpid(pid, &status, WNOHANG) == pid)
         return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      timespec_get(&now, TIME_UTC);
      if ((now.tv_sec - start.tv_sec) >= (time_t)timeout_secs) {
         kill(pid, SIGKILL);
         waitpid(pid, &status, 0);
         if (timed_out) *timed_out = true;
         return -1;
      }
      thrd_sleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100000000}, NULL);
   }
}
