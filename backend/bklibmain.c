#pragma once

#include <windham_const.h>

#include "../library_intrnlsrc/libexit.c"
#include "../library_intrnlsrc/libloop.c"
#include "bklibact.c"
#include "bklibcreat.c"
#include "bklibhelp.c"
#include "bklibkey.c"
#include "bklibopen.c"


void is_running_as_root() {
   if (getuid() != 0) {
     if (setuid(0) == 0){
       return;
     }
      print_error(_("The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible "
                    "without root permission"));
   }
}


void set_oom_score_adj(int value) {
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd == -1) {
        perror("open");
        return;
    }

    char value_str[12];
    snprintf(value_str, sizeof(value_str), "%d", value);

    if (write(fd, value_str, strlen(value_str)) == -1) {
        perror("write");
        close(fd);
        return;
    }

    close(fd);
}

void init() {

   const int speculation_stat = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS);
   if (speculation_stat) { // if the CPU is affected by the speculation misfeature.
      if (!(speculation_stat | PR_SPEC_DISABLE || speculation_stat | PR_SPEC_FORCE_DISABLE)) {
         const bool result = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE, 0, 0) ||
                             prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
         if (result) {
#ifndef WINDHAM_NO_ENFORCE_SPEC_MITIGATION
            if (errno == ENXIO) { // enforced by the kernel parameter
               print_error(_("The build configeration requires Windham to enable speculation mitigation. However, the mitigation is "
                             "disabled and enforced by the kernel parameter. Windham is unable to change this."));
            }
            print_error(
                  _("Can not set speculation mitigation. The build configeration requires Windham to enable speculation mitigation."));
#endif
         }
      }
   }

#ifndef WINDHAM_ALLOW_ATTACH
   // Not dumpable and traceable
   prctl(PR_SET_DUMPABLE, 0);

   char  buffer[256];
   int   tracerPid = 0;
   FILE *fp        = fopen("/proc/self/status", "r");

   while (fgets(buffer, sizeof(buffer), fp)) {
      if (strncmp(buffer, "TracerPid:", 10) == 0) {
         tracerPid = atoi(buffer + 10);
         break;
      }
   }
   fclose(fp);
   if (tracerPid > 0) {
      print_error(_("This process have been traced. Other programs are able to gain full access to Windham. This could compromise the key. "
                    "Windham refuses to run. To debug Windham, rebuild Windham with CMake \"Debug\" profile."));
   }
#endif
   signal(SIGSEGV, segfault_handler);
   signal(SIGINT, sigint_handler);

   set_oom_score_adj(-500);
   get_system_info();
   mapper_init();
}
