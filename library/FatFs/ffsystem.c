/*------------------------------------------------------------------------*/
/* OS Dependent Functions for FatFs — Windham                              */
/*------------------------------------------------------------------------*/
/*
/ Copyright (C) 2025, ChaN, all right reserved.
/ Adapted for Windham ff-driver.
/------------------------------------------------------------------------*/

#include "ff.h"

#if FF_USE_LFN == 3
#include <stdlib.h>
void* ff_memalloc (UINT msize) { return malloc((size_t)msize); }
void ff_memfree (void* mblock)  { free(mblock); }
#endif

#if !FF_FS_READONLY && !FF_FS_NORTC
#include <time.h>
DWORD get_fattime (void)
{
	time_t t = time(NULL);
	struct tm *lt = localtime(&t);
	return (DWORD)(lt->tm_year - 80) << 25
	     | (DWORD)(lt->tm_mon + 1) << 21
	     | (DWORD)lt->tm_mday << 16
	     | (DWORD)lt->tm_hour << 11
	     | (DWORD)lt->tm_min << 5
	     | (DWORD)(lt->tm_sec >> 1);
}
#endif
