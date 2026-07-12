#pragma once


#include "../libsrc/libexit.c"
#include "../libplat/loopctl.c"
#include "bklibact.c"
#include "bklibaux.c"
#include "bklibcreat.c"
#include "bklibhelp.c"
#include "bklibkey.c"
#include "bklibopen.c"
#include "bklibprobe.c"

#include "../include/windham_const.h"


bool is_running_as_root() {
#ifndef WINDHAM_ISOC
   if (getuid() != 0) {
      if (setuid(0) == 0) {
         return true;
      }
      return false;
   }
   return true;
#else
   return true;
#endif
}


#ifndef WINDHAM_ISOC
void set_oom_score_adj(int value) {
   int fd = open("/proc/self/oom_score_adj", O_WRONLY);
   if (fd == -1) {
      perror("open");
      return;
   }

   char value_str[12];
   snprintf(value_str, sizeof(value_str), "%d", value);

   if (write(fd, value_str, strlen(value_str)) == -1) {
      // does nothing.
      close(fd);
      return;
   }

   close(fd);
}

void init(bool is_root, const char *act_driver) {
   const int speculation_stat = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS);
   if (speculation_stat) { // if the CPU is affected by the speculation misfeature.
      if (! (speculation_stat | PR_SPEC_DISABLE || speculation_stat | PR_SPEC_FORCE_DISABLE)) {
         const bool WINDHAM_ATTRIBUTE(maybe_unused) result = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE, 0, 0) ||
                             prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE, 0, 0);
#if WINDHAM_SPEC_MITIGATION != -1
         if (result != 0) {
            if (errno == ENODEV) {
               if (WINDHAM_SPEC_MITIGATION != 2) {
                  print_warning(
                     _("The build configuration requires Windham to enable speculation mitigation, "
                        "and it detects that the system is affected by speculation thus mitigation is required. However, "
                        "Windham has been reported that speculation mitigation is not supported under this system or "
                        "kernel. Did you copied windham to a new system? Windham startup will be delayed for 20 seconds "
                        "to address this issue. Please recompile Windham."));
                  sleep(20);
               }
            } else {
               // EPERM
               if (WINDHAM_SPEC_MITIGATION != 2) {
                  print_error(
                     _("Cannot set speculation mitigation, because the build configuration requires Windham "
                        "to enable speculation mitigation while Windham cannot enable it. Such result might caused by the "
                        "process, which invokes windham, has chose to force disabling it. This is commonly a malicious "
                        "behaviour. Windham refuses to run."));
               }
            }
         }
#endif
      }
   }

#ifndef WINDHAM_ALLOW_ATTACH
   // Not dumpable and traceable
   prctl(PR_SET_DUMPABLE, 0);

   char   buffer[256];
   int    tracerPid = 0;
   FILE * fp        = fopen("/proc/self/status", "r");

   while (fgets(buffer, sizeof(buffer), fp)) {
      if (strncmp(buffer, "TracerPid:", 10) == 0) {
         tracerPid = atoi(buffer + 10);
         break;
      }
   }
   fclose(fp);
   if (tracerPid > 0) {
      print_error(
         _("This process have been traced. Other programs are able to gain full access to Windham. This could compromise the key. "
            "Windham refuses to run. To debug Windham, rebuild Windham with CMake \"Debug\" profile."));
   }
#endif
   signal(SIGSEGV, segfault_handler);
   signal(SIGINT, sigint_handler);

   if (is_root) {
      set_oom_score_adj(-500);
      blkid_init();
   } else {
      set_oom_score_adj(1000);
      is_blkid_available = false;
   }
   driver_init_all(act_driver);
   get_system_info();
}

#else

void init(bool is_root, const char *act_driver) {
    (void)is_root;
    driver_init_all(act_driver);
}
#endif


