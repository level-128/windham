#define _(STRING) gettext(STRING)
#define IS_FRONTEND_ENTRY

#include "main.c"
#include <locale.h>
#include <libintl.h>
#include <windham_const.h>

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
	
  main_(argc, argv);
  return 0;
}
