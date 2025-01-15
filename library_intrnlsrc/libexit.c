#pragma once

#include <stdlib.h>
#include <windham_const.h>
#include <execinfo.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>

#include "libloop.c"
#include "srclib.c"


void windham_exit(int exitno) {
  fin_device();
#ifdef IS_FRONTEND_ENTRY
  if (is_pid1){
    if (exitno == EXIT_SUCCESS){
    printk("Exiting windham, exec %s", init_process);
    execl(init_process, init_process, (char *)NULL);
    } else {
      printk("Windham will exit, panicing the kernel...");
      sleep(2);
      exit(0);
    }
  } else {
    exit(exitno);
  }
   
#else
  if (exitno != EXIT_SUCCESS) {
    longjmp(exit_jmp, 1);
  }
#endif
}


void print_stack_trace() {
#ifdef IS_FRONTEND_ENTRY
#ifdef __GLIBC__
  void * array[40];

  const size_t size    = backtrace(array, 40);
  char **      strings = backtrace_symbols(array, size);

  if (is_pid1){
    printk(_("Caught segmentation fault! Sorry, Windham has crashed.\n"));
    printk(_("Backtrace information:\n\n"));
    for (size_t i = 0; i < size; i++) {
      printk("  %zu: %s\n", i, strings[i]);
    }
  
    free(strings);
    
  } else {
    printf(_("Backtrace information:\n\n"));

    for (size_t i = 0; i < size; i++) {
      printf("  %zu: %s\n", i, strings[i]);
    }
  }
  free(strings);
#else
  printf(_("Backtrace is not available due to incompatible C library.\n"));
#endif
#endif
}


void segfault_handler(__attribute__((unused))int signum) {
#ifdef IS_FRONTEND_ENTRY

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
  print_error_no_exit(_("Caught segmentation fault!"));
  print_stack_trace();
  windham_exit(1);
}


void sigint_handler(__attribute__((unused)) int signum) {
#ifdef IS_FRONTEND_ENTRY

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
  print_error(_("Interrupt signal captured, exiting..."));
  windham_exit(1);
}
