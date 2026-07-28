// libbmp.c — 1-bit BMP file writer for QR code export.
// Packs an N×N monochrome bitmap into Windows BMP format.
#ifndef INCL_LIBBMP
#define INCL_LIBBMP

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Scale factor: each QR module becomes SCALE×SCALE pixels */
#define BMP_SCALE 3

/* Write a square monochrome bitmap to a 1-bit BMP file.
   `modules` is an array of `size`×`size` bools (row-major, y=0 is top).
   Returns 0 on success, -1 on error. */
static int bmp_write(const char *path, const uint8_t *modules,
                     unsigned size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    unsigned px = size * BMP_SCALE;
    unsigned row_bytes = (px + 7) / 8;
    unsigned row_pad   = (4 - (row_bytes & 3)) & 3;
    unsigned pixel_off = 14 + 40 + 8;  /* file hdr + DIB + 2-color table */
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
    di[0] = 40;  /* header size */
    di[4] = px & 0xFF; di[5] = (px >> 8) & 0xFF;
    di[6] = (px >> 16) & 0xFF; di[7] = (px >> 24) & 0xFF;  /* width */
    di[8] = px & 0xFF; di[9] = (px >> 8) & 0xFF;
    di[10] = (px >> 16) & 0xFF; di[11] = (px >> 24) & 0xFF; /* height */
    di[12] = 1; di[13] = 0;  /* planes */
    di[14] = 1; di[15] = 0;  /* bits per pixel */
    di[20] = data_size & 0xFF; di[21] = (data_size >> 8) & 0xFF;
    di[22] = (data_size >> 16) & 0xFF; di[23] = (data_size >> 24) & 0xFF; /* image size */
    fwrite(di, 1, 40, f);

    /* ── Color table: black (0x00,0x00,0x00), white (0xFF,0xFF,0xFF,0x00) ── */
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
            /* 1 = black (module is true/on), 0 = white.
               BMP: 1 bit = white in the color table index sense.
               Our table: index 0 = black, index 1 = white.
               So module true → bit 0 (black), module false → bit 1 (white). */
            if (modules[my * size + mx]) {
                /* black pixel: set bit to 0 */
                /* bit is already 0 */
            } else {
                row[pxi / 8] |= (uint8_t)(0x80 >> (pxi & 7));
            }
        }
        fwrite(row, 1, row_bytes + row_pad, f);
    }
    free(row);
    fclose(f);
    return 0;
}

/* Print a QR code as Unicode blocks to stdout.
   is_color: true → "██", false → "##" for black; "  " for white. */
static void qr_print_terminal(const uint8_t *modules, unsigned size, bool is_color) {
    const char *black = is_color ? "\xe2\x96\x88\xe2\x96\x88" : "##";
    const char *white = "  ";
    for (unsigned y = 0; y < size; y++) {
        for (unsigned x = 0; x < size; x++) {
            fputs(modules[y * size + x] ? black : white, stdout);
        }
        putchar('\n');
    }
}

#endif /* INCL_LIBBMP */
