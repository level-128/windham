#ifndef INCL_LIBEXIT
#define INCL_LIBEXIT

#include <stdlib.h>

#ifndef WINDHAM_ISOC
#ifdef __GLIBC__
#include <execinfo.h>
#endif
#include <sys/prctl.h>
#include <sys/ptrace.h>
#endif

#include "../include/windham_const.h"
#include "../libplat/loopctl.c"
#include "srclib.c"


void windham_exit(int exitno) {
#if defined(WINDHAM_TEST)
   fin_device();
  if (exitno != EXIT_SUCCESS) {
    longjmp(exit_jmp, 1);
  }
#elif defined(IS_FRONTEND_ENTRY) && !defined(WINDHAM_ISOC)
   fin_device();
   if (is_pid1) {
      if (exitno == EXIT_SUCCESS) {
         printk("Exiting windham, exec %s", init_process);
         execl(init_process, init_process, (char *) NULL);
      } else {
         printk("Windham will exit, panicing the kernel...");
         sleep(2);
         exit(0);
      }
   } else {
      exit(exitno);
   }

#elif !defined(IS_FRONTEND_ENTRY) && !defined(WINDHAM_ISOC)
   fin_device();
  if (exitno != EXIT_SUCCESS) {
    longjmp(exit_jmp, 1);
  }
#elif defined(WINDHAM_ISOC)
   exit(exitno);
#endif
}


void print_stack_trace() {
#ifdef IS_FRONTEND_ENTRY
#ifdef __GLIBC__
#include <execinfo.h>
   void * array[40];

   const size_t size    = backtrace(array, 40);
   char **      strings = backtrace_symbols(array, size);

   if (is_pid1) {
      printk(_("Caught segmentation fault! Sorry, Windham has crashed.\n"));
      printk(_("Backtrace information:\n\n"));
      for (size_t i = 0; i < size; i ++) {
         printk("  %zu: %s\n", i, strings[i]);
      }

      free(strings);
   } else {
      printf(_("Backtrace information:\n\n"));

      for (size_t i = 0; i < size; i ++) {
         printf("  %zu: %s\n", i, strings[i]);
      }
   }
   free(strings);
#else
  printf(_("Backtrace is not available due to incompatible C library.\n"));
#endif
#endif
}


#ifndef WINDHAM_ISOC

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

#endif

#endif