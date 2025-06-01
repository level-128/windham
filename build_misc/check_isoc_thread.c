// 0: succ
// 1: error
// 2: stdc no threads.

#include <threads.h>

int work(void *arg) {
   volatile int x1 = 3;
   volatile int x2 = x1 << 2;
   x1 = x2 / 3;
   return 0;
}

int main(void) {
#ifdef __STDC_NO_THREADS__
   return 2;
#else
   thrd_t t;
   int result = thrd_create(&t, work, NULL);
   if (result == thrd_error || result == thrd_nomem) {
      return 1;
   }
   result = thrd_join(t, NULL);
   if (result == thrd_error) {
      return 1;
   }
   return 0;
#endif
}
