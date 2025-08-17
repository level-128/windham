#define IS_FRONTEND_ENTRY

#include <locale.h>

#include "include/windham_const.h"
#include "main.c"

// if ISOC, disable gettext and locale, disable parsing init_str when running under PID1.
#ifndef WINDHAM_ISOC

#include <unistd.h>
#include <stdio.h>

#define INIT_STR				\
u8"/bin/sh\xffOpen\xffTAB"

volatile const char init_str[256] __attribute__((section(".windhaminit"))) = u8"WINDHAMINIT:\xff" INIT_STR;

void parse_and_call() {
  int argc = 0;
  char **argv = NULL;

  size_t len = strlen((const char *)init_str + strlen("WINDHAMINIT:\xff"));
  char *copy = malloc(len + 1);
  memcpy(copy, (const char *)init_str + strlen("WINDHAMINIT:\xff"), len + 1);

  for (size_t i = 0; i < len; i++) {
    if ((unsigned char)copy[i] == 0xff) {
      argc++;
      copy[i] = '\0';
    }
  }
  argc++;

  argv = malloc(argc * sizeof(char *));

  char *ptr = copy;
  for (int i = 0; i < argc; i++) {
    argv[i] = ptr;
    ptr += strlen(ptr) + 1;
  }

  init_process = argv[0];
  main_(argc, argv);

  free(argv);
  free(copy);
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


int main(int argc, char * argv[argc]) {
  is_pid1 = getpid() == 1;

  if (is_pid1){
    parse_and_call();
    exit(0);
  }

  setlocale(LC_ALL, "");
  bindtextdomain("windham", "/usr/share/locale");
  textdomain("windham");
  tcgetattr(STDIN_FILENO, &oldt);

  char self_path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
  if (len == -1) {
    perror("readlink");
    exit(1);
  }
  self_path[len] = '\0';


  if (is_shebang(argv[0], self_path)) {
    if (geteuid() == 0) {
      main_(argc, argv);
    }

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
  main_(argc, argv);
  return 0;
}

#else

#include "library/include_all_libs.c"

int main(int argc, char * argv[]) {
  // detect shell
  // if it is available, we can infer that the terminal should be able to handle color output.
  // this is not good, I know, but we are on ISO C.
  is_has_system_env = system(NULL) != 0;

  // disable inout buffer.
  // will not work on most systems, but we have nothing to do under ISO C
  setvbuf(stdin, NULL, _IONBF, 0);

  main_(argc, argv);
  return 0;
}
#endif
