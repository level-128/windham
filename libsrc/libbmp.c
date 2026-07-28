// libbmp.c — 1-bit BMP file writer for QR code export.
// Packs an N×N monochrome bitmap into Windows BMP format.
#ifndef INCL_LIBBMP
#define INCL_LIBBMP

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/QRCode.h"

/* Scale factor: each QR module becomes SCALE×SCALE pixels */
#define BMP_SCALE 3

/* Write a square monochrome 1-bit BMP file from a QR code.
   Return 0 on success, -1 on error. */
static int bmp_write(const char *path, const QRCode *qr) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    unsigned size   = qr->size;
    unsigned px     = size * BMP_SCALE;
    unsigned row_bytes = (px + 7) / 8;
    unsigned row_pad   = (4 - (row_bytes & 3)) & 3;
    unsigned pixel_off = 14 + 40 + 8;
    unsigned data_size = (row_bytes + row_pad) * px;
    unsigned file_size = pixel_off + data_size;

    /* ── BMP File Header (14 bytes) ── */
    uint8_t bf[14] = {0};
    bf[0] = 'B';  bf[1] = 'M';
    bf[2] = file_size & 0xFF;  bf[3] = (file_size >> 8) & 0xFF;
    bf[4] = (file_size >> 16) & 0xFF; bf[5] = (file_size >> 24) & 0xFF;
    bf[10] = pixel_off & 0xFF; bf[11] = (pixel_off >> 8) & 0xFF;
    fwrite(bf, 1, 14, f);

    /* ── DIB header (BITMAPINFOHEADER, 40 bytes) ── */
    uint8_t di[40] = {0};
    di[0] = 40;
    di[4] = px & 0xFF; di[5] = (px >> 8) & 0xFF;
    di[6] = (px >> 16) & 0xFF; di[7] = (px >> 24) & 0xFF;
    di[8] = px & 0xFF; di[9] = (px >> 8) & 0xFF;
    di[10] = (px >> 16) & 0xFF; di[11] = (px >> 24) & 0xFF;
    di[12] = 1; di[13] = 0;
    di[14] = 1; di[15] = 0;
    di[20] = data_size & 0xFF; di[21] = (data_size >> 8) & 0xFF;
    di[22] = (data_size >> 16) & 0xFF; di[23] = (data_size >> 24) & 0xFF;
    fwrite(di, 1, 40, f);

    /* ── Color table: index 0 = black, index 1 = white ── */
    uint8_t tbl[8] = {0,0,0,0, 0xFF,0xFF,0xFF,0};
    fwrite(tbl, 1, 8, f);

    /* ── Pixel data (bottom row first) ── */
    uint8_t *row = calloc(1, row_bytes + row_pad);
    if (!row) { fclose(f); return -1; }

    for (int py = (int)px - 1; py >= 0; py--) {
        unsigned my = (unsigned)py / BMP_SCALE;
        memset(row, 0, row_bytes + row_pad);
        for (int pxi = 0; pxi < (int)px; pxi++) {
            unsigned mx = (unsigned)pxi / BMP_SCALE;
            /* module true (black) → bit 0; false (white) → bit 1 */
            if (!qrcode_getModule((QRCode *)qr, (uint8_t)mx, (uint8_t)my))
                row[pxi / 8] |= (uint8_t)(0x80 >> (pxi & 7));
        }
        fwrite(row, 1, row_bytes + row_pad, f);
    }
    free(row);
    fclose(f);
    return 0;
}

/* Print a QR code as Unicode blocks to stdout.
   is_color: true → "██", false → "##" for black; "  " for white. */
static void qr_print_terminal(const QRCode *qr, bool is_color) {
    const char *black = is_color ? "\xe2\x96\x88\xe2\x96\x88" : "##";
    const char *white = "  ";
    for (unsigned y = 0; y < qr->size; y++) {
        for (unsigned x = 0; x < qr->size; x++) {
            fputs(qrcode_getModule((QRCode *)qr, (uint8_t)x, (uint8_t)y)
                  ? black : white, stdout);
        }
        putchar('\n');
    }
}

#endif /* INCL_LIBBMP */
