#include <stdlib.h>
#include <windham_const.h>
#include <execinfo.h>
#include <signal.h>

#include "libloop.c"
#include "srclib.c"


void print_stack_trace() {
   #ifdef __GLIBC__
   void *array[40];
   size_t size;
   char **strings;
   size_t i;

   size = backtrace(array, 40);

   strings = backtrace_symbols(array, size);

   printf(_("Backtrace information:\n\n"));

   for (i = 0; i < size; i++) {
      printf("  %zu: %s\n", i, strings[i]);
   }

   free(strings);
   #else
   printf(_("Backtrace is not available due to incompatible C library.\n"));
   #endif
}


void segfault_handler([[maybe_unused]] int signum) {
   print_error_no_exit(_("Caught segmentation fault!"));
   print_stack_trace();
   longjmp(windham_exit, NMOBJ_windham_exit_error);
}


void sigint_handler([[maybe_unused]] int signum){
   print_error(_("Interrupt signal captured, exiting..."));
}

void exit_init(){
	init_libloop();
   signal(SIGSEGV, segfault_handler);
   signal(SIGINT, sigint_handler);
   int jmpval = setjmp(windham_exit);
   if (jmpval == 0) {
      return;
   }
   fin_device();
   if (jmpval == NMOBJ_windham_exit_error){
      exit(EXIT_FAILURE);
   }
   if (jmpval == NMOBJ_windham_exit_normal){
      exit(EXIT_SUCCESS);
   }

}