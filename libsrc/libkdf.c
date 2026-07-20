#include "../include/argon2.h"

#define MEM_ERR(x) (x == NMOBJ_Enclib_alloc_failed_policy_nolock || x == NMOBJ_Enclib_alloc_failed_no_free_mem)

uint64_t kdf_mem_bounds[26][2] = {
   {350, 350}, // 342, 464
   {1480, 1480}, // 932, 1262
   {6100, 6100}, // 2533, 3429
   /* {6887, 9319}, */
   // times e
   {22466, 22469},
   {61071, 61079},
   {166009, 166024},
   {451261, 451332},
   // times 2
   {902522,902702},
   {1805044,1805405},
   {3610088,3610810},
   {7220176,7221620},
   {14440352,14443240},
   {28880704,28886480},
   {57761408,57772960},
   {115522816,115545920},
   {231045632,231091841},
   {462091264,462183682},
   {924182528,924367364},
   {1848365056,1848734729},
   {3696730112,3697469458},
   {7393460224,7394938916},
   {14786920448,14789877832},
   {29573840896,29579755664},
   {59147681792,59159511328},
   {118295363584,118319022656},
   {236590727168,236638045313}
};

const intmax_t t_cost_equal_3_limit = 6100;
const intmax_t t_cost_equal_2_limit = 451332;

static uint32_t kdf_t_cost_for_mem(intmax_t m_cost) {
   if (m_cost <= t_cost_equal_3_limit) return 3;
   if (m_cost <= t_cost_equal_2_limit) return 2;
   return 1;
}

typedef enum {
   NMOBJ_Enclib_calc_okay,
   // okay
   NMOBJ_Enclib_gen_okay_time_reached,
   // okay
   NMOBJ_Enclib_gen_okay_mem_reached,
   // okay
   NMOBJ_Enclib_gen_okay_level_reached,
   // okay
   NMOBJ_Enclib_calc_done,
   // complete
   NMOBJ_Enclib_calc_failed_no_time,
   // no correct pw, no time
   NMOBJ_Enclib_calc_failed_level_exceeded,
   // no correct pw, > max_level
   NMOBJ_Enclib_calc_failed_reached_max_mem,
   // no correct pw, max mem reached
   NMOBJ_Enclib_alloc_failed_policy_nolock,
   // no correct pw, no mem, cannot use unlocked memory when is_allow_nolock == false
   NMOBJ_Enclib_alloc_failed_lock_error,
   // no correct pw, sys error, cannot lock memory
   NMOBJ_Enclib_alloc_failed_no_free_mem,
   // no correct pw, sys error, no memory
} Kdf_step;

/* thread_local result storage; falls back to plain globals
   when C11 threads are not available.  */
#ifndef __STDC_NO_THREADS__
#ifndef WINDHAM_NO_ISOC_THREAD
#include <threads.h>
thread_local Kdf_step Kdf_step_result;
thread_local bool     is_allow_nolock;

#else
Kdf_step Kdf_step_result;
bool is_allow_nolock;

#endif
#else
Kdf_step Kdf_step_result;
bool is_allow_nolock;

#endif

#ifdef WINDHAM_PLAT_GNU_LINUX

#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

// Read MemAvailable and SwapFree from /proc/meminfo (values in KiB).
// Returns 0 on success, -1 if /proc/meminfo cannot be read or parsed.
// MemAvailable is the kernel's own estimate of how much memory is available
// for new allocations without swapping, accounting for reclaimable cache
// and watermark reserves — unlike sysinfo.freeram which only counts free pages.
static int get_mem_available(size_t * mem_available, size_t * swap_free) {
   FILE * fp = fopen("/proc/meminfo", "r");
   if (fp == NULL) {
      return -1;
   }

   *mem_available = 0;
   *swap_free     = 0;

   char line[256];
   while (fgets(line, sizeof(line), fp)) {
      unsigned long val = 0;
      if (strncmp(line, "MemAvailable:", 13) == 0) {
         if (sscanf(line + 13, " %lu", &val) == 1) {
            *mem_available = (size_t)val * 1024; // KiB to bytes
         }
      } else if (strncmp(line, "SwapFree:", 9) == 0) {
         if (sscanf(line + 9, " %lu", &val) == 1) {
            *swap_free = (size_t)val * 1024; // KiB to bytes
         }
      }
   }

   fclose(fp);
   return (*mem_available != 0) ? 0 : -1;
}

// side channel attack defence
size_t search_mem_upper_bound(size_t mem) {
   if (mem < kdf_mem_bounds[0][0] || mem < DEFAULT_MIN_MEMLOCK_SIZE) {
      return mem;
   }
   for (int i = 0; i < KEY_SLOT_EXP_MAX; i++) {
      if (mem > kdf_mem_bounds[i][1]) {
         continue;
      }
      return kdf_mem_bounds[i][1];
   }
   WINDHAM_UNREACHABLE
}


int kdf_memalloc(uint8_t ** result, size_t target_mem) {
   if (target_mem < DEFAULT_MIN_MEMLOCK_SIZE) {
      *result = malloc(target_mem);
      if (*result == NULL) {
         Kdf_step_result = NMOBJ_Enclib_alloc_failed_no_free_mem;
      }
      return 1;
   }

   target_mem = search_mem_upper_bound(target_mem);

   if (is_allow_nolock == false) {
      size_t mem_available, swap_free;
      if (get_mem_available(&mem_available, &swap_free) == 0) {
         if (mem_available < target_mem) {
            *result = NULL;
            if (mem_available + swap_free < target_mem) {
               Kdf_step_result = NMOBJ_Enclib_alloc_failed_no_free_mem;
            } else {
               Kdf_step_result = NMOBJ_Enclib_alloc_failed_policy_nolock;
            }
            return 1;
         }
      }
   }

   const int prot  = PROT_READ | PROT_WRITE;
   const int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;

   *result = mmap(NULL, target_mem, prot, flags, -1, 0);
   if (*result == MAP_FAILED) {
      *result = NULL;
      Kdf_step_result = (errno == ENOMEM)
                        ? NMOBJ_Enclib_alloc_failed_no_free_mem
                        : NMOBJ_Enclib_alloc_failed_lock_error;
      return 1;
   }
   if (is_allow_nolock == false) {
      if (mlock(*result, target_mem) == -1) {
         int lock_errno = errno; // save before munmap potentially modifies it
         munmap(*result, target_mem);
         *result = NULL;
         if (lock_errno == EAGAIN) { // no mem
            Kdf_step_result = NMOBJ_Enclib_alloc_failed_policy_nolock;
         } else if (lock_errno == EPERM || lock_errno == ENOMEM) {
            //   ENOMEM: the caller had a nonzero
            //   RLIMIT_MEMLOCK soft resource limit, but tried to lock more
            //   memory than the limit permitted.  This limit is not
            //   enforced if the process is privileged (CAP_IPC_LOCK).
            //   EPERM: The caller is not privileged, but needs privilege
            //   (CAP_IPC_LOCK) to perform the requested operation.
            Kdf_step_result = NMOBJ_Enclib_alloc_failed_lock_error;
         } else {
            Kdf_step_result = NMOBJ_Enclib_alloc_failed_lock_error;
         }
         return 1;
      }
   }
   return 1;
}

void kdf_memfree(uint8_t * result, size_t target_mem) {
   if (target_mem < DEFAULT_MIN_MEMLOCK_SIZE) {
      free(result);
   } else {
      target_mem = search_mem_upper_bound(target_mem);
      if (munmap(result, target_mem) == -1) {
         perror("munmap");
         windham_exit(2);
      }
   }
}
#else
int kdf_memalloc(uint8_t ** result, const size_t target_mem) {
   *result = malloc(target_mem);
   if (*result == NULL) {
      Kdf_step_result = NMOBJ_Enclib_alloc_failed_no_free_mem;
   }
   return 1;
}

void kdf_memfree(uint8_t * result, const size_t target_mem) {
   free(result);
}

#endif

int kdf_hash(
   const uint32_t t_cost,
   const uint32_t m_cost,
   const uint32_t parallelism,
   const void *   pwd,
   const size_t   pwdlen,
   const void *   salt,
   const size_t   saltlen,
   void *         hash,
   const size_t   hashlen,
   bool           arg_is_allow_nolock) {
   Kdf_step_result = NMOBJ_Enclib_calc_okay;
   is_allow_nolock = arg_is_allow_nolock;

   int result = argon2id_hash_raw(
      t_cost,
      m_cost,
      parallelism,
      pwd,
      pwdlen,
      salt,
      saltlen,
      hash,
      hashlen,
      kdf_memalloc,
      kdf_memfree);

   // ARGON2 errors are always negative, while NMOBJ_Enclib_xxxx are non-negative.
   if (result == ARGON2_OK) {
      result = NMOBJ_Enclib_calc_okay;
   } else if (result == ARGON2_MEMORY_ALLOCATION_ERROR) {
      result = Kdf_step_result;
   } else if (result == ARGON2_MEMORY_TOO_MUCH) {
      Kdf_step_result = NMOBJ_Enclib_calc_failed_reached_max_mem;
      result = Kdf_step_result;
   } else {
      // Unexpected error — treat as fatal
      print_error(_("Argon2 hash failed with error code %d"), result);
   }

   return result;
}
