#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#ifdef __GLIBC__
#include <execinfo.h>
#endif
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include "../../include/windham_const.h"

// Clamp a system memory value to uintptr_t range. On platforms where the
// value does not fit (e.g. 32-bit ix86 with PAE), report UINTPTR_MAX —
// more memory than the address space can address is unusable anyway.
static uintptr_t clamp_meminfo(unsigned long value) {
   if (value > (unsigned long)UINTPTR_MAX) {
      return UINTPTR_MAX;
   }
   return (uintptr_t)value;
}

// Read /proc/meminfo (KiB). On failure, report UINTPTR_MAX (unknown),
// so key derivation always assumes there is enough memory.
void get_system_info() {
   FILE * meminfo = fopen("/proc/meminfo", "r");
   if (meminfo == NULL) {
      sys_info.free_ram  = UINTPTR_MAX;
      sys_info.free_swap = UINTPTR_MAX;
      sys_info.total_ram = UINTPTR_MAX;
      return;
   }

   char          line[256];
   unsigned long memFree  = 0;
   unsigned long memTotal = 0;
   unsigned long cached   = 0;
   unsigned long swapFree = 0;

   while (fgets(line, sizeof(line), meminfo)) {
      if (strncmp(line, "MemFree:", 8) == 0) {
         sscanf(line, "%*s %lu", &memFree);
      } else if (strncmp(line, "MemTotal:", 9) == 0) {
         sscanf(line, "%*s %lu", &memTotal);
      } else if (strncmp(line, "Cached:", 7) == 0) {
         sscanf(line, "%*s %lu", &cached);
      } else if (strncmp(line, "SwapFree:", 9) == 0) {
         sscanf(line, "%*s %lu", &swapFree);
      }
   }

   sys_info.free_ram  = clamp_meminfo(memFree + cached);
   sys_info.free_swap = clamp_meminfo(swapFree);
   sys_info.total_ram = clamp_meminfo(memTotal);

   fclose(meminfo);
}

bool should_use_color(void) {
    if (getenv("NO_COLOR") != NULL) {
        return false;
    }
    if (!isatty(STDOUT_FILENO)) {
        return false;
    }
    return true;
}

#ifndef WINDHAM_NO_SHEBANG_ENTRY

#include <sys/auxv.h>

bool is_shebang(const char * args0, const char * self_path) {
  char shebang[16];
  for (int i = 2; shebang_line[i] != 0; i++) {
    shebang[i - 2] = shebang_line[i] == '\n' ? 0 : shebang_line[i];
  }
  if (strcmp(args0, shebang) != 0) {
    return false;
  }

  char * auxval = (char *)getauxval(AT_EXECFN);
  if (auxval == NULL) {
    return false;
  }
  if (strcmp(args0, auxval) == 0) {
    return false;
  }

  if (strcmp(self_path, auxval) == 0) {
    return false;
  }
  return true;
}

#else
bool is_shebang(const char * WINDHAM_ATTRIBUTE(maybe_unused) args0,
                const char * WINDHAM_ATTRIBUTE(maybe_unused) self_path) {
  return false;
}
#endif

/**
 * Install a seccomp-BPF denylist that blocks dangerous syscall families.
 * Also locks in PR_SET_NO_NEW_PRIVS (required by seccomp).
 *
 * Allowed syscalls pass through to SECCOMP_RET_ALLOW.  Forbidden ones
 * return SECCOMP_RET_KILL_PROCESS -- the kernel kills the entire process
 * with SIGSYS on violation.
 *
 * Windham itself never needs any of the blocked categories, so this
 * filter applies to the main process as well as to forked shell-aux
 * children (which later add their own stricter filters on top).
 *
 * Returns true if seccomp is available and the filter was installed.
 */
static bool seccomp_init(void) {
#define DENY(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

    struct sock_filter denylist[] = {
        /* load syscall number from seccomp_data */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

#include "../../include/seccomp_denylist.c"

        /* default: allow everything else */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = sizeof(denylist) / sizeof(denylist[0]),
        .filter = denylist,
    };

#undef DENY

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return false;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
        return false;

    return true;
}

/* ── Signal handlers ────────────────────────────────────────── */

static void print_stack_trace(void) {
#ifdef __GLIBC__
   void * array[40];

   const size_t size    = backtrace(array, 40);
   char **      strings = backtrace_symbols(array, size);

   printf(_("Backtrace information:\n\n"));

   for (size_t i = 0; i < size; i ++) {
      printf("  %zu: %s\n", i, strings[i]);
   }
   free(strings);
#endif
}

static void segfault_handler(__attribute__((unused)) int signum) {
#ifdef IS_FRONTEND_ENTRY
   tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
   fprintf(stderr, "%s\n", _("Caught segmentation fault!"));
   print_stack_trace();
   windham_exit(1);
}

static void sigint_handler(__attribute__((unused)) int signum) {
#ifdef IS_FRONTEND_ENTRY
   tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
   fprintf(stderr, "%s\n", _("Interrupt signal captured, exiting..."));
   windham_exit(1);
}


void frontend_init(int argc, char *argv[]){

  init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_SYSTEM;

  char self_path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
  if (len == -1) {
    perror("readlink");
    exit(1);
  }
  self_path[len] = '\0';

  init_val->is_shebang = is_shebang(argv[0], self_path);

  if (init_val->is_shebang) {
    if (geteuid() != 0) {
      char absolute_path[PATH_MAX];
      if (realpath(argv[1], absolute_path) == NULL) {
        perror("realpath");
        exit(1);
      }
      char *pkexec_args[] = {
        "pkexec",
        self_path,
        "Open",
        absolute_path,
        NULL
    };

      execvp("pkexec", pkexec_args);
      perror("pkexec");
      exit(1);
    }
  }

  // Shell aux auto-execution is allowed only when seccomp is available
  // (so child processes can be sandboxed).
#ifndef WINDHAM_NO_SECCOMP
  init_val->is_secure_env = seccomp_init();
#else
  init_val->is_secure_env = false;
#endif

  setlocale(LC_ALL, "");
  bindtextdomain("windham", "/usr/share/locale");
  textdomain("windham");
  tcgetattr(STDIN_FILENO, &oldt);
  signal(SIGSEGV, segfault_handler);
  signal(SIGINT, sigint_handler);

  init_val->is_color_print = should_use_color();
}