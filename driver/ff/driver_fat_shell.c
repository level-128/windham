// driver_fat_shell.c -- FatFs shell driver for Windham (single file)
// Reads a decrypted block device, mounts FAT/exFAT, provides
// an interactive shell for browsing the filesystem.
//
// Only available when WINDHAM_UTF_16 is defined (C11 uchar.h).


#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>

#include "../../include/windham_const.h"
#include "../../libsrc/srclib.c"
#include "../../library/FatFs/ff.h"
#include "../../library/FatFs/diskio.h"

/* ====================================================================== */
/*  Shell                                                                  */
/* ====================================================================== */

static FATFS      g_FatFs;
static int        Mounted = 0;

#define COPY_BUF_SIZE  65536
static BYTE        CopyBuf[COPY_BUF_SIZE];

#define MAX_PATH       512
static TCHAR        TPathBuf[MAX_PATH];
static char         CwdBuf[MAX_PATH];
static TCHAR        TPathBuf2[MAX_PATH];

/*-----------------------------------------------------------------------*/
/* String conversion: C-string (ASCII) <-> TCHAR (char16_t)             */
/*-----------------------------------------------------------------------*/

static void cstr_to_tchar(TCHAR *dst, const char *src, size_t dsize)
{
	size_t i, j;
	for (i = 0, j = 0; j + 1 < dsize && src[i]; ) {
		if (src[i] == '\\' && src[i+1]) {
			int is_wide = (src[i+1] == 'U');
			if (src[i+1] == 'u' || is_wide) {
				int ndigits = is_wide ? 8 : 4;
				DWORD val = 0;
				int k;
				for (k = 0; k < ndigits && src[i+2+k]; k++) {
					char c = src[i+2+k];
					if (c >= '0' && c <= '9')
						val = (val << 4) | (DWORD)(c - '0');
					else if (c >= 'A' && c <= 'F')
						val = (val << 4) | (DWORD)(c - 'A' + 10);
					else if (c >= 'a' && c <= 'f')
						val = (val << 4) | (DWORD)(c - 'a' + 10);
					else break;
				}
				if (k == ndigits) {
					i += (size_t)(2 + ndigits);
					if (is_wide && val >= 0x10000 && val <= 0x10FFFF) {
						val -= 0x10000;
						dst[j++] = (TCHAR)(0xD800 | (val >> 10));
						if (j + 1 < dsize)
							dst[j++] = (TCHAR)(0xDC00 | (val & 0x3FF));
					} else {
						dst[j++] = (TCHAR)val;
					}
					continue;
				}
			}
		}
#if !defined(WINDHAM_UTF_16)
		if ((unsigned char)src[i] >= 128) { i++; continue; }
#endif
		dst[j++] = (TCHAR)(unsigned char)src[i++];
	}
	dst[j] = 0;
}

static void tchar_to_cstr(char *dst, const TCHAR *src, size_t dsize)
{
#define IsSurrogateH(c) ((c) >= 0xD800 && (c) <= 0xDBFF)
#define IsSurrogateL(c) ((c) >= 0xDC00 && (c) <= 0xDFFF)
	size_t i, j;
	for (i = 0, j = 0; j + 1 < dsize && src[i]; i++) {
		if (src[i] < 128) {
			dst[j++] = (char)src[i];
#if defined(WINDHAM_UTF_16)
		} else {
			dst[j++] = '?';
#else
		} else if (IsSurrogateH(src[i]) && src[i+1] && IsSurrogateL(src[i+1])) {
			if (j + 11 <= dsize) {
				DWORD cp = 0x10000 + (((DWORD)src[i] - 0xD800) << 10)
				           + ((DWORD)src[i+1] - 0xDC00);
				j += (size_t)snprintf(&dst[j], 11, "\\U%08lX",
				                      (unsigned long)cp);
				i++;
			}
		} else if (j + 7 <= dsize) {
			j += (size_t)snprintf(&dst[j], 7, "\\u%04X",
			                      (unsigned)src[i]);
#endif
		}
	}
#undef IsSurrogateH
#undef IsSurrogateL
	dst[j] = 0;
}

static size_t tchar_len(const TCHAR *s)
{
	size_t n = 0;
	while (*s++) n++;
	return n;
}

static int tchar_cmp(const TCHAR *a, const TCHAR *b)
{
	while (*a && *b && *a == *b) { a++; b++; }
	return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static void tchar_cpy(TCHAR *dst, const TCHAR *src)
{
	while ((*dst++ = *src++));
}

static void tchar_ncpy(TCHAR *dst, const TCHAR *src, size_t n)
{
	size_t i;
	for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
	for (; i < n; i++) dst[i] = 0;
}

/*-----------------------------------------------------------------------*/
/* Path utilities                                                        */
/*-----------------------------------------------------------------------*/

static void get_cwd_display(void)
{
	FRESULT fr;
#if FF_FS_RPATH >= 2
	TCHAR buf[MAX_PATH];
	fr = f_getcwd(buf, MAX_PATH);
	if (fr == FR_OK) {
		tchar_to_cstr(CwdBuf, buf, MAX_PATH);
		if (CwdBuf[0] == '0' && CwdBuf[1] == ':') {
			size_t len = strlen(CwdBuf + 2);
			memmove(CwdBuf, CwdBuf + 2, len + 1);
		}
		if (CwdBuf[0] == '\0') { CwdBuf[0] = '/'; CwdBuf[1] = '\0'; }
		return;
	}
#endif
	strcpy(CwdBuf, "/");
}

static void print_fresult(FRESULT fr, const char *op)
{
	if (fr == FR_OK) return;
	static const char *tbl[] = {
		"FR_OK", "FR_DISK_ERR", "FR_INT_ERR", "FR_NOT_READY",
		"FR_NO_FILE", "FR_NO_PATH", "FR_INVALID_NAME", "FR_DENIED",
		"FR_EXIST", "FR_INVALID_OBJECT", "FR_WRITE_PROTECTED",
		"FR_INVALID_DRIVE", "FR_NOT_ENABLED", "FR_NO_FILESYSTEM",
		"FR_MKFS_ABORTED", "FR_TIMEOUT", "FR_LOCKED",
		"FR_NOT_ENOUGH_CORE", "FR_TOO_MANY_OPEN_FILES", "FR_INVALID_PARAMETER"
	};
	const char *name = (fr <= FR_INVALID_PARAMETER) ? tbl[fr] : "???";
	fprintf(stderr, "%s: %s (%d)\n", op, name, (int)fr);
}

static const TCHAR *basename_tchar(const TCHAR *path)
{
	const TCHAR *p = path + tchar_len(path);
	while (p > path && *(p - 1) != u'/' && *(p - 1) != u'\\') p--;
	return p;
}

static void user_path_to_tchar(TCHAR *dst, size_t dsize, const char *src)
{
	cstr_to_tchar(dst, src, dsize);
}

/*-----------------------------------------------------------------------*/
/* Formatting helpers for ls -l                                          */
/*-----------------------------------------------------------------------*/

static void format_size(char *buf, size_t bufsz, FSIZE_t sz)
{
	static const char *units[] = {"B", "Ki", "Mi", "Gi", "Ti", "Pi", NULL};
	int ui = 0;
	double dsz = (double)(QWORD)sz;
	while (dsz >= 1024.0 && units[ui + 1]) { dsz /= 1024.0; ui++; }
	if (ui == 0)
		snprintf(buf, bufsz, "%llu", (unsigned long long)(QWORD)sz);
	else
		snprintf(buf, bufsz, "%.1f%s", dsz, units[ui]);
}

static void format_attr(char *buf, const FILINFO *fno)
{
	buf[0] = (fno->fattrib & AM_DIR) ? 'd' : '-';
	buf[1] = 'r'; buf[2] = 'w'; buf[3] = '-';
	buf[4] = 'r'; buf[5] = 'w'; buf[6] = '-';
	buf[7] = 'r'; buf[8] = 'w'; buf[9] = '-';
	buf[10] = '\0';
}

static void format_date(char *buf, size_t bufsz, WORD fdate)
{
	int y = ((fdate >> 9) & 0x7F) + 1980;
	int m = (fdate >> 5) & 0x0F;
	int d = fdate & 0x1F;
	snprintf(buf, bufsz, "%04d-%02d-%02d", y, m, d);
}

static void format_time(char *buf, size_t bufsz, WORD ftime)
{
	int h = (ftime >> 11) & 0x1F;
	int mi = (ftime >> 5) & 0x3F;
	int s = (ftime & 0x1F) * 2;
	snprintf(buf, bufsz, "%02d:%02d:%02d", h, mi, s);
}

/*-----------------------------------------------------------------------*/
/* ls [-lha] [path]                                                      */
/*-----------------------------------------------------------------------*/

static int cmd_ls(int argc, char **argv)
{
	int opt_l = 0, opt_h = 0, opt_a = 0;
	const char *path = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			const char *o = argv[i] + 1;
			while (*o) {
				if (*o == 'l') opt_l = 1;
				else if (*o == 'h') opt_h = 1;
				else if (*o == 'a') opt_a = 1;
				else { fprintf(stderr, "ls: unknown option '%c'\n", *o); return 1; }
				o++;
			}
		} else {
			path = argv[i];
		}
	}

	user_path_to_tchar(TPathBuf, MAX_PATH, path ? path : ".");

	FATFS_DIR dir;
	FRESULT fr = f_opendir(&dir, TPathBuf);
	if (fr != FR_OK) { print_fresult(fr, "ls"); return 1; }

	FILINFO fno;
	while ((fr = f_readdir(&dir, &fno)) == FR_OK && fno.fname[0]) {
		char name[MAX_PATH];
		tchar_to_cstr(name, fno.fname, MAX_PATH);

		if (!opt_a && name[0] == '.') continue;

		if (opt_l) {
			char attr[16], szstr[32], dstr[32], tstr[32];
			format_attr(attr, &fno);
			if (opt_h)
				format_size(szstr, sizeof(szstr), fno.fsize);
			else
				snprintf(szstr, sizeof(szstr), "%llu", (unsigned long long)(QWORD)fno.fsize);
			format_date(dstr, sizeof(dstr), fno.fdate);
			format_time(tstr, sizeof(tstr), fno.ftime);

			printf("%-10s %8s  %s %s  %s",
			       attr, szstr, dstr, tstr, name);
			if (fno.fattrib & AM_DIR) printf("/");
			printf("\n");
		} else {
			printf("%s", name);
			if (fno.fattrib & AM_DIR) printf("/");
			printf("  ");
		}
	}

	if (!opt_l) printf("\n");
	f_closedir(&dir);
	return 0;
}

/*-----------------------------------------------------------------------*/
/* cd <path>                                                             */
/*-----------------------------------------------------------------------*/

static int cmd_cd(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "cd: missing path\n");
		return 1;
	}
	user_path_to_tchar(TPathBuf, MAX_PATH, argv[1]);
	FRESULT fr = f_chdir(TPathBuf);
	if (fr != FR_OK) { print_fresult(fr, "cd"); return 1; }
	return 0;
}

/*-----------------------------------------------------------------------*/
/* cp [-r] <src> <dst>                                                   */
/*-----------------------------------------------------------------------*/

static FRESULT cp_file(const TCHAR *src, const TCHAR *dst)
{
	FIL fsrc, fdst;
	FRESULT fr = f_open(&fsrc, src, FA_READ);
	if (fr != FR_OK) return fr;

	fr = f_open(&fdst, dst, FA_WRITE | FA_CREATE_ALWAYS);
	if (fr != FR_OK) { f_close(&fsrc); return fr; }

	for (;;) {
		UINT br;
		fr = f_read(&fsrc, CopyBuf, COPY_BUF_SIZE, &br);
		if (fr != FR_OK || br == 0) break;
		UINT bw;
		fr = f_write(&fdst, CopyBuf, br, &bw);
		if (fr != FR_OK || bw < br) { fr = FR_DISK_ERR; break; }
	}

	f_close(&fdst);
	f_close(&fsrc);
	return fr;
}

static FRESULT cp_dir_recursive(const TCHAR *src, const TCHAR *dst);

static FRESULT cp_dir_entry(const TCHAR *srcdir, const TCHAR *dstdir, const FILINFO *fno)
{
	size_t slen = tchar_len(srcdir);
	size_t dlen = tchar_len(dstdir);
	size_t nlen = tchar_len(fno->fname);

	TCHAR *srcfull = (TCHAR*)malloc((slen + 1 + nlen + 1) * sizeof(TCHAR));
	TCHAR *dstfull = (TCHAR*)malloc((dlen + 1 + nlen + 1) * sizeof(TCHAR));
	if (!srcfull || !dstfull) { free(srcfull); free(dstfull); return FR_DENIED; }

	tchar_ncpy(srcfull, srcdir, slen);
	srcfull[slen] = u'/';
	tchar_cpy(srcfull + slen + 1, fno->fname);

	tchar_ncpy(dstfull, dstdir, dlen);
	dstfull[dlen] = u'/';
	tchar_cpy(dstfull + dlen + 1, fno->fname);

	FRESULT fr;
	if (fno->fattrib & AM_DIR) {
		fr = f_mkdir(dstfull);
		if (fr == FR_OK || fr == FR_EXIST)
			fr = cp_dir_recursive(srcfull, dstfull);
	} else {
		fr = cp_file(srcfull, dstfull);
	}

	free(srcfull);
	free(dstfull);
	return fr;
}

static FRESULT cp_dir_recursive(const TCHAR *src, const TCHAR *dst)
{
	FATFS_DIR dir;
	FRESULT fr = f_opendir(&dir, src);
	if (fr != FR_OK) return fr;

	FILINFO fno;
	while ((fr = f_readdir(&dir, &fno)) == FR_OK && fno.fname[0]) {
		if (tchar_cmp(fno.fname, u".") == 0 || tchar_cmp(fno.fname, u"..") == 0)
			continue;
		fr = cp_dir_entry(src, dst, &fno);
		if (fr != FR_OK) break;
	}
	f_closedir(&dir);
	return fr;
}

static int cmd_cp(int argc, char **argv)
{
	int opt_r = 0;
	int path_start = 1;

	if (argc >= 2 && strcmp(argv[1], "-r") == 0) {
		opt_r = 1;
		path_start = 2;
	}

	if (argc - path_start < 2) {
		fprintf(stderr, "cp: missing operand\nUsage: cp [-r] <src> <dst>\n");
		return 1;
	}

	const char *srcstr = argv[path_start];
	const char *dststr = argv[path_start + 1];

	user_path_to_tchar(TPathBuf, MAX_PATH, srcstr);
	user_path_to_tchar(TPathBuf2, MAX_PATH, dststr);

	FILINFO fno;
	FRESULT fr = f_stat(TPathBuf, &fno);
	if (fr != FR_OK) { print_fresult(fr, "cp"); return 1; }

	int src_is_dir = (fno.fattrib & AM_DIR) != 0;
	if (src_is_dir && !opt_r) {
		fprintf(stderr, "cp: '%s' is a directory (use -r)\n", srcstr);
		return 1;
	}

	if (src_is_dir) {
		FILINFO dstfno;
		FRESULT dfr = f_stat(TPathBuf2, &dstfno);
		if (dfr == FR_OK && (dstfno.fattrib & AM_DIR)) {
			const TCHAR *bn = basename_tchar(TPathBuf);
			size_t dlen = tchar_len(TPathBuf2);
			TCHAR *dst_with_base = (TCHAR*)malloc((dlen + 1 + tchar_len(bn) + 1) * sizeof(TCHAR));
			tchar_ncpy(dst_with_base, TPathBuf2, dlen);
			dst_with_base[dlen] = u'/';
			tchar_cpy(dst_with_base + dlen + 1, bn);
			fr = f_mkdir(dst_with_base);
			if (fr == FR_OK || fr == FR_EXIST)
				fr = cp_dir_recursive(TPathBuf, dst_with_base);
			free(dst_with_base);
		} else {
			fr = f_mkdir(TPathBuf2);
			if (fr == FR_OK || fr == FR_EXIST)
				fr = cp_dir_recursive(TPathBuf, TPathBuf2);
		}
	} else {
		FILINFO dstfno;
		FRESULT dfr = f_stat(TPathBuf2, &dstfno);
		if (dfr == FR_OK && (dstfno.fattrib & AM_DIR)) {
			const TCHAR *bn = basename_tchar(TPathBuf);
			size_t dlen = tchar_len(TPathBuf2);
			TCHAR *dst_with_base = (TCHAR*)malloc((dlen + 1 + tchar_len(bn) + 1) * sizeof(TCHAR));
			tchar_ncpy(dst_with_base, TPathBuf2, dlen);
			dst_with_base[dlen] = u'/';
			tchar_cpy(dst_with_base + dlen + 1, bn);
			fr = cp_file(TPathBuf, dst_with_base);
			free(dst_with_base);
		} else {
			fr = cp_file(TPathBuf, TPathBuf2);
		}
	}

	if (fr != FR_OK) print_fresult(fr, "cp");
	return (fr == FR_OK) ? 0 : 1;
}

/*-----------------------------------------------------------------------*/
/* mv <src> <dst>                                                        */
/*-----------------------------------------------------------------------*/

static int cmd_mv(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "mv: missing operand\nUsage: mv <src> <dst>\n");
		return 1;
	}

	user_path_to_tchar(TPathBuf, MAX_PATH, argv[1]);
	user_path_to_tchar(TPathBuf2, MAX_PATH, argv[2]);

	FRESULT fr = f_rename(TPathBuf, TPathBuf2);
	if (fr != FR_OK) { print_fresult(fr, "mv"); return 1; }
	return 0;
}

/*-----------------------------------------------------------------------*/
/* rm [-r] <path>                                                        */
/*-----------------------------------------------------------------------*/

static FRESULT rm_dir_recursive(const TCHAR *path)
{
	FATFS_DIR dir;
	FRESULT fr = f_opendir(&dir, path);
	if (fr != FR_OK) return fr;

	FILINFO fno;
	size_t plen = tchar_len(path);
	TCHAR *full = (TCHAR*)malloc((plen + 1 + MAX_PATH) * sizeof(TCHAR));
	if (!full) { f_closedir(&dir); return FR_DENIED; }

	while ((fr = f_readdir(&dir, &fno)) == FR_OK && fno.fname[0]) {
		char ename[MAX_PATH];
		tchar_to_cstr(ename, fno.fname, MAX_PATH);
		if (strcmp(ename, ".") == 0 || strcmp(ename, "..") == 0) continue;

		tchar_ncpy(full, path, plen);
		full[plen] = u'/';
		tchar_cpy(full + plen + 1, fno.fname);

		if (fno.fattrib & AM_DIR) {
			fr = rm_dir_recursive(full);
		} else {
			fr = f_unlink(full);
		}
		if (fr != FR_OK) break;
	}

	free(full);
	f_closedir(&dir);
	if (fr == FR_OK) fr = f_unlink(path);
	return fr;
}

static int cmd_rm(int argc, char **argv)
{
	int opt_r = 0;
	const char *target = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0) opt_r = 1;
		else if (!target) target = argv[i];
	}

	if (!target) {
		fprintf(stderr, "rm: missing operand\nUsage: rm [-r] <path>\n");
		return 1;
	}

	user_path_to_tchar(TPathBuf, MAX_PATH, target);

	FILINFO fno;
	FRESULT fr = f_stat(TPathBuf, &fno);
	if (fr != FR_OK) { print_fresult(fr, "rm"); return 1; }

	if (fno.fattrib & AM_DIR) {
		if (!opt_r) {
			fprintf(stderr, "rm: '%s' is a directory (use -r)\n", target);
			return 1;
		}
		fr = rm_dir_recursive(TPathBuf);
	} else {
		fr = f_unlink(TPathBuf);
	}

	if (fr != FR_OK) { print_fresult(fr, "rm"); return 1; }
	return 0;
}

/*-----------------------------------------------------------------------*/
/* find -name <pattern> [path]                                           */
/*-----------------------------------------------------------------------*/

static int cmd_find(int argc, char **argv)
{
	const char *pattern = NULL;
	const char *path = ".";
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
			pattern = argv[++i];
		} else if (argv[i][0] != '-') {
			path = argv[i];
		} else {
			fprintf(stderr, "find: unknown option '%s'\n", argv[i]);
			return 1;
		}
	}

	if (!pattern) {
		fprintf(stderr, "find: missing -name pattern\nUsage: find -name <pattern> [path]\n");
		return 1;
	}

	user_path_to_tchar(TPathBuf, MAX_PATH, path);
	cstr_to_tchar(TPathBuf2, pattern, MAX_PATH);

	FATFS_DIR dir;
	FILINFO fno;
	FRESULT fr = f_findfirst(&dir, &fno, TPathBuf, TPathBuf2);
	if (fr == FR_NO_FILE) return 0;
	if (fr != FR_OK) { print_fresult(fr, "find"); return 1; }

	do {
		char name[MAX_PATH];
		tchar_to_cstr(name, fno.fname, MAX_PATH);
		printf("%s/%s", path, name);
		if (fno.fattrib & AM_DIR) printf("/");
		printf("\n");
	} while ((fr = f_findnext(&dir, &fno)) == FR_OK && fno.fname[0]);

	f_closedir(&dir);
	return 0;
}

/*-----------------------------------------------------------------------*/
/* import <host-path> <fat-path>                                         */
/*-----------------------------------------------------------------------*/

static int cmd_import(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "import: missing operand\nUsage: import <host-path> <fat-path>\n");
		return 1;
	}

	FILE *hf = fopen(argv[1], "rb");
	if (!hf) { perror("import: fopen host"); return 1; }

	user_path_to_tchar(TPathBuf, MAX_PATH, argv[2]);

	FIL ff;
	FRESULT fr = f_open(&ff, TPathBuf, FA_WRITE | FA_CREATE_ALWAYS);
	if (fr != FR_OK) { print_fresult(fr, "import"); fclose(hf); return 1; }

	for (;;) {
		size_t nr = fread(CopyBuf, 1, COPY_BUF_SIZE, hf);
		if (nr == 0) break;
		UINT bw;
		fr = f_write(&ff, CopyBuf, (UINT)nr, &bw);
		if (fr != FR_OK || bw != (UINT)nr) {
			if (fr == FR_OK) fr = FR_DISK_ERR;
			break;
		}
	}

	f_close(&ff);
	fclose(hf);
	if (fr != FR_OK) { print_fresult(fr, "import"); return 1; }
	return 0;
}

/*-----------------------------------------------------------------------*/
/* Tar helpers                                                           */
/*-----------------------------------------------------------------------*/

#define TAR_BLOCK  512

static void tar_octal(char *dst, size_t len, QWORD val)
{
	dst[--len] = '\0';
	if (val == 0) {
		while (len > 0) dst[--len] = '0';
		dst[0] = '0';
		return;
	}
	while (len > 0 && val > 0) {
		dst[--len] = (char)('0' + (int)(val & 7));
		val >>= 3;
	}
	while (len > 0) dst[--len] = '0';
}

static void tar_checksum(char *header)
{
	int i;
	unsigned sum = 0;
	for (i = 0; i < 148; i++) sum += (unsigned char)header[i];
	for (i = 0; i < 8; i++) sum += ' ';
	for (i = 156; i < TAR_BLOCK; i++) sum += (unsigned char)header[i];
	tar_octal(header + 148, 7, sum);
	header[155] = ' ';
}

static QWORD fat_time_to_unix(WORD fdate, WORD ftime)
{
	int y = ((fdate >> 9) & 0x7F) + 1980;
	int m = (fdate >> 5) & 0x0F;
	int d = fdate & 0x1F;
	int hh = (ftime >> 11) & 0x1F;
	int mm = (ftime >> 5) & 0x3F;
	int ss = (ftime & 0x1F) * 2;

	static const int mdays[] = {31,28,31,30,31,30,31,31,30,31,30,31};
	QWORD days = 0;
	int yi;
	for (yi = 1970; yi < y; yi++)
		days += (yi % 4 == 0 && (yi % 100 != 0 || yi % 400 == 0)) ? 366 : 365;
	for (yi = 1; yi < m; yi++) {
		days += mdays[yi - 1];
		if (yi == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) days++;
	}
	days += (d - 1);
	return days * 86400 + hh * 3600 + mm * 60 + ss;
}

static void tar_emit_header(FILE *hf, const char *name, const FILINFO *fno)
{
	char header[TAR_BLOCK];
	memset(header, 0, TAR_BLOCK);

	size_t nlen = strlen(name);
	if (nlen < 100) {
		memcpy(header, name, nlen);
	} else {
		size_t split = nlen;
		while (split > 0 && name[split] != '/') split--;
		if (split > 0 && split <= 155 && (nlen - split - 1) <= 100) {
			memcpy(header, name + split + 1, nlen - split - 1);
			memcpy(header + 345, name, split);
		} else {
			memcpy(header, name, 99);
		}
	}

	if (fno->fattrib & AM_DIR) {
		header[156] = '5';
		tar_octal(header + 124, 12, 0);
	} else {
		header[156] = '0';
		tar_octal(header + 124, 12, (QWORD)fno->fsize);
	}

	tar_octal(header + 100, 8, (fno->fattrib & AM_DIR) ? 0755 : 0644);
	tar_octal(header + 108, 8, 0);
	tar_octal(header + 116, 8, 0);
	tar_octal(header + 136, 12, fat_time_to_unix(fno->fdate, fno->ftime));
	memcpy(header + 257, "ustar", 5);
	header[263] = '0';
	header[264] = '0';
	memset(header + 297, ' ', 8);

	tar_checksum(header);
	fwrite(header, 1, TAR_BLOCK, hf);
}

static FRESULT tar_emit_file_content(FILE *hf, const TCHAR *fatpath)
{
	FIL ff;
	FRESULT fr = f_open(&ff, fatpath, FA_READ);
	if (fr != FR_OK) return fr;

	for (;;) {
		UINT br;
		fr = f_read(&ff, CopyBuf, COPY_BUF_SIZE, &br);
		if (fr != FR_OK || br == 0) break;
		if (fwrite(CopyBuf, 1, br, hf) != br) { fr = FR_DISK_ERR; break; }
	}
	f_close(&ff);

	FSIZE_t sz = f_size(&ff);
	UINT pad = (UINT)((TAR_BLOCK - (sz % TAR_BLOCK)) % TAR_BLOCK);
	if (pad) {
		memset(CopyBuf, 0, pad);
		fwrite(CopyBuf, 1, pad, hf);
	}
	return fr;
}

static FRESULT tar_export_dir_recursive(FILE *hf, const TCHAR *fatdir, const char *tardir)
{
	FATFS_DIR dir;
	FRESULT fr = f_opendir(&dir, fatdir);
	if (fr != FR_OK) return fr;

	size_t tdlen = strlen(tardir);

	FILINFO fno;
	while ((fr = f_readdir(&dir, &fno)) == FR_OK && fno.fname[0]) {
		char ename[MAX_PATH];
		tchar_to_cstr(ename, fno.fname, MAX_PATH);

		if (strcmp(ename, ".") == 0 || strcmp(ename, "..") == 0) continue;

		char tarname[MAX_PATH];
		int n = snprintf(tarname, MAX_PATH, "%s%s%s",
		                 tardir, (*tardir && tardir[tdlen - 1] != '/') ? "/" : "", ename);
		if (n < 0 || n >= MAX_PATH) continue;

		size_t flen = tchar_len(fatdir);
		size_t elen = tchar_len(fno.fname);
		TCHAR *fatfull = (TCHAR*)malloc((flen + 1 + elen + 1) * sizeof(TCHAR));
		if (!fatfull) { f_closedir(&dir); return FR_DENIED; }
		tchar_ncpy(fatfull, fatdir, flen);
		fatfull[flen] = u'/';
		tchar_cpy(fatfull + flen + 1, fno.fname);

		tar_emit_header(hf, tarname, &fno);

		if (!(fno.fattrib & AM_DIR)) {
			fr = tar_emit_file_content(hf, fatfull);
		} else {
			fr = tar_export_dir_recursive(hf, fatfull, tarname);
		}
		free(fatfull);
		if (fr != FR_OK) break;
	}
	f_closedir(&dir);
	return fr;
}

/*-----------------------------------------------------------------------*/
/* export <fat-path> <host-path>                                         */
/*-----------------------------------------------------------------------*/

static int cmd_export(int argc, char **argv)
{
	int opt_tar = 0;
	const char *fatpath = NULL;
	const char *hostpath = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-tar") == 0) {
			opt_tar = 1;
		} else if (!fatpath) {
			fatpath = argv[i];
		} else if (!hostpath) {
			hostpath = argv[i];
		}
	}

	if (!fatpath || !hostpath) {
		fprintf(stderr, "export: missing operand\nUsage: export [-tar] <fat-path> <host-path>\n");
		return 1;
	}

	user_path_to_tchar(TPathBuf, MAX_PATH, fatpath);

	FILINFO fno;
	FRESULT fr = f_stat(TPathBuf, &fno);
	if (fr != FR_OK) { print_fresult(fr, "export"); return 1; }

	FILE *hf = fopen(hostpath, "wb");
	if (!hf) { perror("export: fopen host"); return 1; }

	if (fno.fattrib & AM_DIR) {
		if (!opt_tar) {
			fprintf(stderr, "export: '%s' is a directory (use -tar)\n", fatpath);
			return 1;
		}
		const char *bn = fatpath;
		{
			const char *p = bn + strlen(bn);
			while (p > bn && *(p - 1) != '/' && *(p - 1) != '\\') p--;
			bn = p;
		}

		tar_emit_header(hf, bn, &fno);
		fr = tar_export_dir_recursive(hf, TPathBuf, bn);
		if (fr == FR_OK) {
			memset(CopyBuf, 0, TAR_BLOCK * 2);
			fwrite(CopyBuf, 1, TAR_BLOCK * 2, hf);
		}
	} else {
		FIL ff;
		fr = f_open(&ff, TPathBuf, FA_READ);
		if (fr == FR_OK) {
			for (;;) {
				UINT br;
				fr = f_read(&ff, CopyBuf, COPY_BUF_SIZE, &br);
				if (fr != FR_OK || br == 0) break;
				if (fwrite(CopyBuf, 1, br, hf) != br) { fr = FR_DISK_ERR; break; }
			}
			f_close(&ff);
		}
	}

	fclose(hf);
	if (fr != FR_OK) { print_fresult(fr, "export"); return 1; }
	return 0;
}

/*-----------------------------------------------------------------------*/
/* df                                                                    */
/*-----------------------------------------------------------------------*/

static int cmd_df(void)
{
	FATFS *fs;
	DWORD free_clst;
	FRESULT fr = f_getfree(u"", &free_clst, &fs);
	if (fr != FR_OK) { print_fresult(fr, "df"); return 1; }

	QWORD total_clst = fs->n_fatent - 2;
	QWORD used_clst  = total_clst - free_clst;
	DWORD csize      = fs->csize;
	WORD  ssize      = (FF_MAX_SS != FF_MIN_SS) ? fs->ssize : FF_MIN_SS;
	QWORD total_bytes = total_clst * csize * ssize;
	QWORD free_bytes  = free_clst  * csize * ssize;
	QWORD used_bytes  = used_clst  * csize * ssize;
	int pct = total_clst ? (int)(used_clst * 100 / total_clst) : 0;

	char tbuf[32], ubuf[32], fbuf[32];
	format_size(tbuf, sizeof(tbuf), (FSIZE_t)total_bytes);
	format_size(ubuf, sizeof(ubuf), (FSIZE_t)used_bytes);
	format_size(fbuf, sizeof(fbuf), (FSIZE_t)free_bytes);

	printf("  %10s  %10s  %10s  Use%%  Type\n", "Total", "Used", "Free");
	printf("  %10s  %10s  %10s  %3d%%  %s\n",
	       tbuf, ubuf, fbuf, pct,
	       (fs->fs_type == FS_FAT12) ? "FAT12" :
	       (fs->fs_type == FS_FAT16) ? "FAT16" :
	       (fs->fs_type == FS_FAT32) ? "FAT32" :
	       (fs->fs_type == FS_EXFAT) ? "exFAT" : "?");
	return 0;
}

/*-----------------------------------------------------------------------*/
/* help                                                                  */
/*-----------------------------------------------------------------------*/

static int cmd_help(void)
{
	printf(
		"Commands:\n"
		"  ls [-lha] [path]           List directory contents\n"
		"  cd <path>                  Change working directory\n"
		"  cp [-r] <src> <dst>        Copy file(s)\n"
		"  mv <src> <dst>             Move / rename\n"
		"  find -name <pat> [path]    Find files (wildcards: * ?)\n"
		"  import <host> <fat>        Copy host file into image\n"
		"  export <fat> <host>        Copy image file to host\n"
		"  rm [-r] <path>             Delete file(s)\n"
		"  df                         Show disk usage\n"
		"  help                       Show this help\n"
		"  exit / quit                Exit shell\n"
	);
	return 0;
}

/*-----------------------------------------------------------------------*/
/* Command dispatcher                                                    */
/*-----------------------------------------------------------------------*/

static int exec_command(int argc, char **argv)
{
	if (argc == 0) return 0;
	if (strcmp(argv[0], "ls") == 0)           return cmd_ls(argc, argv);
	if (strcmp(argv[0], "cd") == 0)           return cmd_cd(argc, argv);
	if (strcmp(argv[0], "cp") == 0)           return cmd_cp(argc, argv);
	if (strcmp(argv[0], "mv") == 0)           return cmd_mv(argc, argv);
	if (strcmp(argv[0], "rm") == 0)           return cmd_rm(argc, argv);
	if (strcmp(argv[0], "find") == 0)         return cmd_find(argc, argv);
	if (strcmp(argv[0], "import") == 0)       return cmd_import(argc, argv);
	if (strcmp(argv[0], "export") == 0)       return cmd_export(argc, argv);
	if (strcmp(argv[0], "df") == 0)           return cmd_df();
	if (strcmp(argv[0], "help") == 0)         return cmd_help();
	fprintf(stderr, "Unknown command: %s\nType 'help' for available commands.\n", argv[0]);
	return 1;
}

/*-----------------------------------------------------------------------*/
/* Tokenizer                                                             */
/*-----------------------------------------------------------------------*/

static int tokenize(char *line, char **argv, int max_args)
{
	int argc = 0;
	char *p = line;

	while (*p && argc < max_args) {
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
		if (*p == '\0') break;

		if (*p == '"' || *p == '\'') {
			char quote = *p++;
			argv[argc++] = p;
			while (*p && *p != quote) p++;
			if (*p) *p++ = '\0';
		} else {
			argv[argc++] = p;
			while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
			if (*p) *p++ = '\0';
		}
	}

	return argc;
}

/*-----------------------------------------------------------------------*/
/* Shell entry point                                                     */
/*-----------------------------------------------------------------------*/

static int ff_shell_run(void)
{
	FRESULT fr;

	fr = f_mount(&g_FatFs, u"0:", 1);
	if (fr != FR_OK) {
		print_fresult(fr, "f_mount");
		return -1;
	}
	Mounted = 1;

	f_chdir(u"/");

	BYTE fs_type = g_FatFs.fs_type;
	const char *type_str =
		(fs_type == FS_FAT12) ? "FAT12" :
		(fs_type == FS_FAT16) ? "FAT16" :
		(fs_type == FS_FAT32) ? "FAT32" :
		(fs_type == FS_EXFAT) ? "exFAT" : "?";

	printf("Filesystem type: %s\n", type_str);
	printf("Type 'help' for available commands.\n\n");

	char line[4096];
	char *line_argv[64];

	for (;;) {
		get_cwd_display();
		printf("fat:%s> ", CwdBuf);
		fflush(stdout);

		if (!fgets(line, sizeof(line), stdin)) break;

		int nargs = tokenize(line, line_argv, 64);
		if (nargs == 0) continue;

		if (strcmp(line_argv[0], "exit") == 0 || strcmp(line_argv[0], "quit") == 0)
			break;

		exec_command(nargs, line_argv);
	}

	if (Mounted) {
		f_mount(NULL, u"0:", 0);
		Mounted = 0;
	}

	return 0;
}

/* ====================================================================== */
/*  Driver vtable                                                          */
/* ====================================================================== */

static int ff_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void ff_hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++)
        bin[i] = (uint8_t)((ff_hex_nibble(hex[i * 2]) << 4) | ff_hex_nibble(hex[i * 2 + 1]));
}

static void ff_init(const char *driver_name)
{
    (void)driver_name;
    is_device_mapper_available = true;
}

static int ff_try_create(const char *f, const char *e, const char *t)
{
    (void)f; (void)e; (void)t;
    return EMOBJ_try_create_crypt_mapping_OK;
}

static int ff_create(
    const char *device, const char *name, const char *enc_type,
    const char *password, char uuid_str[37],
    size_t start_sector, size_t end_sector, size_t block_size,
    bool is_read_only, bool is_allow_discards,
    bool is_no_read_workqueue, bool is_no_write_workqueue)
{
    (void)name;
    (void)is_read_only;
    (void)is_allow_discards;
    (void)is_no_read_workqueue;
    (void)is_no_write_workqueue;

    if (!enc_type || strncmp(enc_type, "aes-xts", 7) != 0)
        print_error(_("ff driver requires aes-xts encryption (got '%s')."), enc_type);

    size_t key_size = DEFAULT_DISK_KEY_SIZE_BYTES;
    uint8_t *disk_key = calloc(1, key_size);
    if (!disk_key) { perror("malloc"); exit(1); }
    ff_hex_to_bin(password, disk_key, key_size);

    void *dev_handle = device_open(device, false);
    if (!dev_handle) { perror(device); exit(1); }

    size_t part_sectors = end_sector - start_sector;
    ff_diskio_init(dev_handle, disk_key, block_size, start_sector, part_sectors, 0);

    printf("UUID:   %s\n", uuid_str);
    printf("Device: %s\n", device);

    int ret = ff_shell_run();

    free(disk_key);
    device_close(dev_handle);
    return ret;
}

static bool ff_linear_map(const char *d, const char *n, uint64_t s, uint64_t sz, const char *u)
{
    (void)d; (void)n; (void)s; (void)sz; (void)u;
    return false;
}

static void ff_map_partitions(const char *n, bool b) { (void)n; (void)b; }

Driver driver_ff = {
    .name               = "ff",
    .init               = ff_init,
    .try_create         = ff_try_create,
    .create             = ff_create,
    .remove             = NULL,
    .remove_by_uuid     = NULL,
    .linear_map         = ff_linear_map,
    .map_partition_table = ff_map_partitions,
};
