/*------------------------------------------------------------------------*/
/* Unicode Handling Functions for FatFs R0.13 and Later                   */
/*------------------------------------------------------------------------*/
/* OEM code page support removed. Uses C11 mbrtoc16/c16rtomb for          */
/* locale-based multibyte conversion.                                     */
/*------------------------------------------------------------------------*/
/*
/ Copyright (C) 2022, ChaN, all right reserved.
/
/ FatFs module is an open source software. Redistribution and use of FatFs in
/ source and binary forms, with or without modification, are permitted provided
/ that the following condition is met:
/
/ 1. Redistributions of source code must retain the above copyright notice,
/    this condition and the following disclaimer.
/
/ This software is provided by the copyright holder and contributors "AS IS"
/ and any warranties related to this software are DISCLAIMED.
/ The copyright owner or contributors be NOT LIABLE for any damages caused
/ by use of this software.
*/


#include "ff.h"
#include <uchar.h>
#include <wchar.h>
#include <wctype.h>

#if FF_USE_LFN != 0	/* This module will be blanked if in non-LFN configuration */


/*------------------------------------------------------------------------*/
/* OEM <==> Unicode Conversions (via C11 locale-based multibyte)          */
/*------------------------------------------------------------------------*/

WCHAR ff_uni2oem (	/* Returns OEM code character, zero on error */
	DWORD	uni,	/* UTF-16 encoded character to be converted */
	WORD	cp		/* Code page for the conversion (ignored, locale-based) */
)
{
	(void)cp;
	if (uni < 0x80) return (WCHAR)uni;
#if defined(__STDC_UTF_16__)
	if (uni < 0x10000) {
		char s[4];
		mbstate_t state = {0};
		size_t n = c16rtomb(s, (char16_t)uni, &state);
		if (n == 1) return (WCHAR)(BYTE)s[0];
	}
#endif
	return 0;
}


WCHAR ff_oem2uni (	/* Returns Unicode character in UTF-16, zero on error */
	WCHAR	oem,	/* OEM code to be converted */
	WORD	cp		/* Code page for the conversion (ignored, locale-based) */
)
{
	(void)cp;
	if (oem < 0x80) return oem;
#if defined(__STDC_UTF_16__)
	{
		char s[2] = { (char)oem, 0 };
		char16_t c16 = 0;
		mbstate_t state = {0};
		size_t rc = mbrtoc16(&c16, s, 1, &state);
		if (rc != (size_t)-1 && rc != (size_t)-2) return c16;
	}
#endif
	return 0;
}


/*------------------------------------------------------------------------*/
/* Unicode Up-case Conversion (via C11 towupper)                          */
/*------------------------------------------------------------------------*/

DWORD ff_wtoupper (	/* Returns up-converted code point */
	DWORD uni		/* Unicode code point to be up-converted */
)
{
#if defined(__STDC_UTF_16__)
	wint_t up = towupper((wint_t)uni);
	return (up != WEOF) ? (DWORD)up : uni;
#else
	if (uni >= 'a' && uni <= 'z') return uni - 0x20;
	return uni;
#endif
}


#endif /* #if FF_USE_LFN != 0 */
