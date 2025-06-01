#ifndef INCL_CHK_ENC_SUPP_STAT
#define INCL_CHK_ENC_SUPP_STAT

void action_new_check_crypt_support_status(const char *);

#ifndef WINDHAM_ISOC
#include "GNU_Linux/chk_enc_supp_stat.c"
#else
#include "ISOC/chk_enc_supp_stat.c"
#endif

#endif