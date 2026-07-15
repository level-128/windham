// aes_xts_impl.c -- userspace XTS-AES compatible with Linux dm-crypt
//
// plain64 IV mode: each sector gets IV = le64(sector_number) || 0x00*8.
// IV is constructed as explicit little-endian bytes -> host-endianness agnostic.
// Large sectors (512–4096) use the same IV for all sub-512-blocks;
// the XTS tweak chain differentiates every 16-byte AES block within the sector.
//
// Key: 2 * AES_KEYLEN bytes.  First half = data key, second half = tweak key.
// For AES-256-XTS: key is 64 bytes.

#ifndef INCL_AES_XTS_IMPL
#define INCL_AES_XTS_IMPL

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "../include/aes.h"

// ---- GF(2^128) multiplication by x --------------------------------------------
// "ble" convention (big-endian bits within little-endian bytes):
//   byte 0 = GF bits   0..7    (bit 0 = LSB of byte 0 = GF coefficient of x^0)
//   byte 15 = GF bits 120..127  (bit 7 = MSB of byte 15 = GF coefficient of x^127)
//
// Multiplication: T * x, with reduction polynomial x^128 + x^7 + x^2 + x + 1.
// Overflow from GF bit 127 -> XOR 0x87 at byte 0.
static void gf128mul_x_ble(uint8_t t[16]) {
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t next = t[i] >> 7;
        t[i] = (uint8_t)((t[i] << 1) | carry);
        carry = next;
    }
    if (carry) t[0] ^= 0x87;
}


// ---- plain64 IV ----------------------------------------------------------------------------------
// IV[0..7] = le64(logical_sector), IV[8..15] = 0
static void make_plain64_iv(uint8_t iv[16], uint64_t sector) {
    memset(iv, 0, 16);
    iv[0] = (uint8_t)(sector);
    iv[1] = (uint8_t)(sector >> 8);
    iv[2] = (uint8_t)(sector >> 16);
    iv[3] = (uint8_t)(sector >> 24);
    iv[4] = (uint8_t)(sector >> 32);
    iv[5] = (uint8_t)(sector >> 40);
    iv[6] = (uint8_t)(sector >> 48);
    iv[7] = (uint8_t)(sector >> 56);
}


// ---- single-sector XTS encrypt / decrypt --------------------------------
// data  : in-place buffer, exactly sector_size_bytes long
// key   : 2 * AES_KEYLEN bytes (data key || tweak key)
// iv    : 16-byte IV (from make_plain64_iv)
// encrypt: true -> encrypt, false -> decrypt
static void aes_xts_crypt_sector(
    uint8_t *      data,
    size_t         sector_size_bytes,
    const uint8_t  key[2 * AES_KEYLEN],
    const uint8_t  iv[16],
    bool           encrypt)
{
    // sector_size_bytes must be >= 512, a power-of-two multiple of 512,
    // and a multiple of 16 (AES block size).
    // 512=2^9, 1024=2^10, 2048=2^11, 4096=2^12 -- all satisfy these.
    struct AES_ctx data_ctx, tweak_ctx;

    AES_init_ctx(&data_ctx,  key);              // Key1 = data key (first half, xts_setkey:key)
    AES_init_ctx(&tweak_ctx, key + AES_KEYLEN); // Key2 = tweak key (second half, xts_setkey:key+keylen)

    // T_0 = AES_ECB_enc(Key2, IV)
    uint8_t tweak[16];
    memcpy(tweak, iv, 16);
    AES_ECB_encrypt(&tweak_ctx, tweak);

    size_t blocks = sector_size_bytes / 16;

    for (size_t b = 0; b < blocks; b++) {
        // Pre-whiten
        for (int i = 0; i < 16; i++)
            data[b * 16 + i] ^= tweak[i];

        // ECB with data key
        if (encrypt)
            AES_ECB_encrypt(&data_ctx, &data[b * 16]);
        else
            AES_ECB_decrypt(&data_ctx, &data[b * 16]);

        // Post-whiten
        for (int i = 0; i < 16; i++)
            data[b * 16 + i] ^= tweak[i];

        // T_{k+1} = T_k * x
        gf128mul_x_ble(tweak);
    }
}


// ---- Public API ----------------------------------------------------------------------------------

// Encrypt sector_count consecutive sectors starting from start_sector.
// data: in-place buffer, sector_count * sector_size_bytes bytes.
// sector_size_bytes must be >= 512 and a multiple of 16 (AES_BLOCKLEN).
void aes_xts_encrypt_sectors(
    uint8_t *      data,
    uint64_t       sector_count,
    const uint8_t  key[2 * AES_KEYLEN],
    uint64_t       start_sector,
    unsigned int   sector_size_bytes)
{
    for (uint64_t s = 0; s < sector_count; s++) {
        uint8_t iv[16];
        make_plain64_iv(iv, start_sector + s);
        aes_xts_crypt_sector(
            data + s * (size_t)sector_size_bytes,
            sector_size_bytes, key, iv, true);
    }
}


// Decrypt: same API, internal direction reversed.
void aes_xts_decrypt_sectors(
    uint8_t *      data,
    uint64_t       sector_count,
    const uint8_t  key[2 * AES_KEYLEN],
    uint64_t       start_sector,
    unsigned int   sector_size_bytes)
{
    for (uint64_t s = 0; s < sector_count; s++) {
        uint8_t iv[16];
        make_plain64_iv(iv, start_sector + s);
        aes_xts_crypt_sector(
            data + s * (size_t)sector_size_bytes,
            sector_size_bytes, key, iv, false);
    }
}

#endif
