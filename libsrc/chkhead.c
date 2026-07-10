#ifndef INCL_CHKHEAD
#define INCL_CHKHEAD

#include <limits.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include "../include/windham_const.h"

#if (__STDC_VERSION__ >= 202311L)
#include <stdbit.h>
#endif

int popcount64(uint64_t x) {
#if (__STDC_VERSION__ >= 202311L)
    return stdc_count_ones(x);
#elif defined(__GNUC__)
    return __builtin_popcountll(x);
#else
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (x * 0x0101010101010101ULL) >> 56;
#endif
}

size_t count_ones(const uint8_t *data, size_t length) {
    assert(length % sizeof(uint64_t) == 0);
    size_t total = 0;
    for (size_t i = 0; i < length; i += sizeof(uint64_t)) {
        union { 
            uint8_t u8[8]; 
            uint64_t u64; 
        } word;
        for (int j = 0; j < 8; j++) word.u8[j] = data[i + j];
        total += popcount64(word.u64);
    }
    return total;
}

static double inverse_normal_cdf(double p) {

    const double a1 = -39.6968302866538;
    const double a2 = 220.946098424521;
    const double a3 = -275.928510446969;
    const double a4 = 138.357751867269;
    const double a5 = -30.6647980661472;
    const double a6 = 2.50662827745924;

    const double b1 = -54.4760987982241;
    const double b2 = 161.585836858041;
    const double b3 = -155.698979859887;
    const double b4 = 66.8013118877197;
    const double b5 = -13.2806815528857;

    const double c1 = -7.78489400243029e-03;
    const double c2 = -0.322396458041136;
    const double c3 = -2.40075827716184;
    const double c4 = -2.54973253934373;
    const double c5 = 4.37466414146497;
    const double c6 = 2.93816398269878;

    const double d1 = 7.78469570904146e-03;
    const double d2 = 0.32246712907004;
    const double d3 = 2.445134137143;
    const double d4 = 3.75440866190742;

    const double p_low = 0.02425;
    const double p_high = 1 - p_low;

    double q, r;

    if (p < p_low) {
        // Rational approximation for lower region
        q = sqrt(-2 * log(p));
        return (((((c1 * q + c2) * q + c3) * q + c4) * q + c5) * q + c6) /
               ((((d1 * q + d2) * q + d3) * q + d4) * q + 1);
    } else if (p > p_high) {
        // Rational approximation for upper region
        q = sqrt(-2 * log(1 - p));
        return -(((((c1 * q + c2) * q + c3) * q + c4) * q + c5) * q + c6) /
                ((((d1 * q + d2) * q + d3) * q + d4) * q + 1);
    } else {
        // Rational approximation for central region
        q = p - 0.5;
        r = q * q;
        return (((((a1 * r + a2) * r + a3) * r + a4) * r + a5) * r + a6) * q /
               (((((b1 * r + b2) * r + b3) * r + b4) * r + b5) * r + 1);
    }
}

bool check_head(Data * data) {
    // False-positive rate for each individual test.
    // Combined rate ≤ 3 × p ≈ 3e-8 for a truly random header.
    double p = 1e-8;

    size_t N = (sizeof(Data) - offsetof(Data, master_key_mask)) * CHAR_BIT;

    // ── Test 1: binomial bit-proportion (lower-tail) ──────────
    // Treat each bit as an independent coin flip.  Reject if the
    // observed fraction of 1-bits is too far below 0.5.
    double z_lower = inverse_normal_cdf(1.0 - p / 2.0);
    double ratio_diff = z_lower / (2.0 * sqrt((double)N));
    uint32_t count_of_1 = (uint32_t)((1.0 - ratio_diff) * (double)N / 2.0);
    size_t ones = count_ones((unsigned char *)data + offsetof(Data, master_key_mask), N / CHAR_BIT);
    if (ones < count_of_1) return false;

    size_t byte_count = sizeof(Data) - offsetof(Data, master_key_mask);
    const uint8_t *bytes = (const uint8_t *)data + offsetof(Data, master_key_mask);

    // ── Test 2: MTF + chi-squared uniformity (upper-tail) ─────
    // Move-to-front encode the byte stream, then test whether MTF
    // positions are uniformly distributed via chi-squared (df=255).
    // Using normal approximation: critical = df + z * sqrt(2*df).
    uint8_t mtf[256];
    for (int i = 0; i < 256; i++) mtf[i] = (uint8_t)i;
    uint64_t freq[256] = {0};

    for (size_t i = 0; i < byte_count; i++) {
        uint8_t b = bytes[i];
        int pos = 0;
        while (mtf[pos] != b) pos++;
        freq[pos]++;
        memmove(mtf + 1, mtf, (size_t)pos);
        mtf[0] = b;
    }

    double expected = (double)byte_count / 256.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 256; i++) {
        double d = (double)freq[i] - expected;
        chi_sq += d * d / expected;
    }
    double z_upper = inverse_normal_cdf(1.0 - p);
    double chi_crit = 255.0 + z_upper * sqrt(2.0 * 255.0);
    if (chi_sq > chi_crit) return false;

    // ── Test 3: 2D random walk (two-sided) ────────────────────
    // 2 bits per axis per byte drive a random walk.  For truly
    // random data, the squared displacement D² has E[D²] = N and
    // SD[D²] = N.  Reject if |D² - N| exceeds z * N.
    int64_t wx = 0, wy = 0;
    for (size_t i = 0; i < byte_count; i++) {
        uint8_t b = bytes[i];
        switch (b & 3) { case 0: wx--; break; case 3: wx++; break; default: break; }
        switch ((b >> 2) & 3) { case 0: wy--; break; case 3: wy++; break; default: break; }
    }
    double ed2 = (double)byte_count;
    double ad2 = (double)(wx * wx + wy * wy);
    double sd  = (double)byte_count;
    double z_two = inverse_normal_cdf(1.0 - p / 2.0);
    if (fabs(ad2 - ed2) > z_two * sd) return false;

    return true;
}


#endif

