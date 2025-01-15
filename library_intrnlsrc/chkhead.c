#include <limits.h>
#include <math.h>
#include <windham_const.h>

#ifndef INCL_CHKHEAD
#define INCL_CHKHEAD

size_t count_ones(const unsigned char *data, size_t length) {
    size_t total = 0;
    for (size_t i = 0; i < length; ++i) {
        total += __builtin_popcount(data[i]);
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

bool check_head(Data data) {
    double p = 1e-8;
    size_t N = (sizeof(data) - sizeof(data.head) - sizeof(data.uuid_and_salt) -
		sizeof(data._unused)) * CHAR_BIT;

    double z = inverse_normal_cdf(1 - p / 2);

    double ratio_diff = z / (2 * sqrt(N));

    uint32_t count_of_1 = (N - ratio_diff * N) / 2;
    return count_ones((unsigned char *)&data, N / CHAR_BIT) >= count_of_1;
}


#endif

