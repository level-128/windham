/*-----------------------------------------------------------------------*/
/* Low level disk interface module include file   (C)ChaN, 2025          */
/* Adapted for Windham — encrypted block device I/O                      */
/*-----------------------------------------------------------------------*/

#ifndef _DISKIO_DEFINED
#define _DISKIO_DEFINED

#include "ff.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef BYTE DSTATUS;

typedef enum {
	RES_OK = 0, RES_ERROR, RES_WRPRT, RES_NOTRDY, RES_PARERR
} DRESULT;

#define STA_NOINIT  0x01
#define STA_NODISK  0x02
#define STA_PROTECT 0x04

#define CTRL_SYNC        0
#define GET_SECTOR_COUNT 1
#define GET_SECTOR_SIZE  2
#define GET_BLOCK_SIZE   3
#define CTRL_TRIM        4

DSTATUS disk_initialize (BYTE pdrv);
DSTATUS disk_status (BYTE pdrv);
DRESULT disk_read (BYTE pdrv, BYTE* buff, LBA_t sector, UINT count);
DRESULT disk_write (BYTE pdrv, const BYTE* buff, LBA_t sector, UINT count);
DRESULT disk_ioctl (BYTE pdrv, BYTE cmd, void* buff);

void ff_diskio_init(int fd, const uint8_t *xts_key,
                    size_t sector_size, size_t part_start, size_t part_sectors,
                    int writable);

#ifdef __cplusplus
}
#endif

#endif
