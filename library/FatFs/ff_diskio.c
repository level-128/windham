/*-----------------------------------------------------------------------*/
/* Encrypted disk I/O for block device — Windham                         */
/*-----------------------------------------------------------------------*/
/* Reads and writes sectors on a raw block device, encrypting/decrypting */
/* with XTS-AES on the fly.  When writable==0, disk_write returns        */
/* RES_WRPRT (read‑only).                                                */
/*-----------------------------------------------------------------------*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "diskio.h"

void aes_xts_decrypt_sectors(uint8_t *buf, uint64_t num_sectors,
                             const uint8_t *key, uint64_t start_sector,
                             unsigned int sector_size);
void aes_xts_encrypt_sectors(uint8_t *buf, uint64_t num_sectors,
                             const uint8_t *key, uint64_t start_sector,
                             unsigned int sector_size);

static int           dev_fd       = -1;
static const uint8_t *xts_key    = NULL;
static size_t        sector_size  = 512;
static size_t        part_start   = 0;
static size_t        part_sectors = 0;
static int           writable     = 0;

void ff_diskio_init(int fd, const uint8_t *key,
                    size_t ss, size_t start, size_t count, int wr)
{
	dev_fd       = fd;
	xts_key      = key;
	sector_size  = ss;
	part_start   = start;
	part_sectors = count;
	writable     = wr;
}

DSTATUS disk_status(BYTE pdrv)
{
	(void)pdrv;
	return (dev_fd >= 0) ? 0 : STA_NOINIT;
}

DSTATUS disk_initialize(BYTE pdrv)
{
	(void)pdrv;
	return (dev_fd >= 0) ? 0 : STA_NOINIT;
}

DRESULT disk_read(BYTE pdrv, BYTE *buff, LBA_t sector, UINT count)
{
	(void)pdrv;
	if (dev_fd < 0) return RES_NOTRDY;
	if (count == 0)  return RES_PARERR;

	size_t ratio = sector_size / 512;
	size_t bytes = (size_t)count * sector_size;
	off_t  off   = (off_t)((part_start + (size_t)sector) * sector_size);

	if (lseek(dev_fd, off, SEEK_SET) == (off_t)-1)
		return RES_ERROR;
	if (read(dev_fd, buff, bytes) != (ssize_t)bytes)
		return RES_ERROR;

	for (UINT i = 0; i < count; i++) {
		uint64_t iv = (uint64_t)((part_start + (size_t)(sector + i)) * ratio);
		aes_xts_decrypt_sectors(buff + (size_t)i * sector_size,
		                        1, xts_key, iv, sector_size);
	}

	return RES_OK;
}

DRESULT disk_write(BYTE pdrv, const BYTE *buff, LBA_t sector, UINT count)
{
	(void)pdrv;
	if (dev_fd < 0) return RES_NOTRDY;
	if (!writable)   return RES_WRPRT;
	if (count == 0)  return RES_PARERR;

	size_t ratio = sector_size / 512;
	size_t bytes = (size_t)count * sector_size;
	off_t  off   = (off_t)((part_start + (size_t)sector) * sector_size);

	/* encrypt into a temporary buffer, then write */
	BYTE *enc = (BYTE *)malloc(bytes);
	if (!enc) return RES_ERROR;
	memcpy(enc, buff, bytes);

	for (UINT i = 0; i < count; i++) {
		uint64_t iv = (uint64_t)((part_start + (size_t)(sector + i)) * ratio);
		aes_xts_encrypt_sectors(enc + (size_t)i * sector_size,
		                        1, xts_key, iv, sector_size);
	}

	if (lseek(dev_fd, off, SEEK_SET) == (off_t)-1) {
		free(enc);
		return RES_ERROR;
	}
	if (write(dev_fd, enc, bytes) != (ssize_t)bytes) {
		free(enc);
		return RES_ERROR;
	}

	free(enc);
	return RES_OK;
}

DRESULT disk_ioctl(BYTE pdrv, BYTE cmd, void *buff)
{
	(void)pdrv;
	switch (cmd) {
	case CTRL_SYNC:
		return RES_OK;
	case GET_SECTOR_COUNT:
		*(LBA_t *)buff = (LBA_t)part_sectors;
		return RES_OK;
	case GET_SECTOR_SIZE:
		*(WORD *)buff = (WORD)sector_size;
		return RES_OK;
	case GET_BLOCK_SIZE:
		*(DWORD *)buff = 1;
		return RES_OK;
	case CTRL_TRIM:
		return RES_OK;
	default:
		return RES_PARERR;
	}
}
