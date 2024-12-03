/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"
#include <openssl/sha.h>

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"

/* 256^-1 mod kPrime, in Montgomery form */
static const uint32_t kInverseDegreeMontgomery = 41978;

static const uint32_t kNTTRootsMontgomery[256] = {
    4193792, 25847,   5771523, 7861508, 237124,  7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776,   3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944,  531354,  954230,  3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944,  508951,  3097992, 44288,   7280319, 904516,  3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969,  7063561,
    189548,  4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997,  2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702,  1859098, 909542,  819034,  495491,  6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297,  286988,  5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191,  2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136,  4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,  7173032,
    5196991, 162844,  1616392, 3014001, 810149,  1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760,  2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443,  7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782
};

    /*
     * @brief Computes x *
     * See FIPS 204 Algorithm 49
     */
//declassify_assert(x <= ((uint64_t)kPrime << 32));
//declassify_assert((b & 0xffffffff) == 0);
static uint32_t reduce_montgomery(uint64_t x)
{
    uint64_t a = (uint32_t)x * (uint32_t)ML_DSA_Q_NEG_INV;
    uint64_t b = x + a * ML_DSA_Q;
    uint32_t c = b >> 32;

    return reduce_once(c);
}

// Multiply two polynomials in the number theoretically transformed state.
void ossl_ml_dsa_poly_ntt_mult(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = reduce_montgomery((uint64_t)lhs->coeff[i] * (uint64_t)rhs->coeff[i]);
}

/*
 * In place number theoretic transform of a given scalar.
 *
 * See FIPS 204, Algorithm 41 (`NTT`).
 */
void ossl_ml_dsa_poly_ntt(POLY *s)
{
    int i, j, k;
    int step; /* step is powers of 2 (1, 2, 4, 8, ..., 128) */
    int offset = ML_DSA_NUM_POLY_COEFFICIENTS; /* offset is powers of 2 (128, 64, ..., 1) */
// Step: 1, 2, 4, 8, ..., 128
// Offset: 128, 64, 32, 16, ..., 1
    for (step = 1; step < ML_DSA_NUM_POLY_COEFFICIENTS; step <<= 1) {
        k = 0;
        offset >>= 1;
        for (i = 0; i < step; i++) {
          //assert(k == 2 * offset * i);
          const uint32_t step_root = kNTTRootsMontgomery[step + i];
          for (j = k; j < k + offset; j++) {
            uint32_t even = s->coeff[j];
            // |reduce_montgomery| works on values up to kPrime*R and R > 2*kPrime.
            // |step_root| < kPrime because it's static data. |s->c[...]| is <
            // kPrime by the invariants of that struct.
            uint32_t odd =
                reduce_montgomery((uint64_t)step_root * (uint64_t)s->coeff[j + offset]);
            s->coeff[j] = reduce_once(odd + even);
            s->coeff[j + offset] = mod_sub(even, odd);
          }
          k += 2 * offset;
        }
    }
}

// In place inverse number theoretic transform of a given scalar.
//
// FIPS 204, Algorithm 42 (`NTT^-1`).
void ossl_ml_dsa_poly_ntt_inverse(POLY *s)
{
    // Step: 128, 64, 32, 16, ..., 1
    // Offset: 1, 2, 4, 8, ..., 128
    int i, j, k, offset, step = ML_DSA_NUM_POLY_COEFFICIENTS;

    for (offset = 1; offset < ML_DSA_NUM_POLY_COEFFICIENTS; offset <<= 1) {
        step >>= 1;
        k = 0;
        for (i = 0; i < step; i++) {
            //assert(k == 2 * offset * i);
            const uint32_t step_root = ML_DSA_Q - kNTTRootsMontgomery[step + (step - 1 - i)];
            for (j = k; j < k + offset; j++) {
                uint32_t even = s->coeff[j];
                uint32_t odd = s->coeff[j + offset];
                s->coeff[j] = reduce_once(odd + even);

                // |reduce_montgomery| works on values up to kPrime*R and R > 2*kPrime.
                // kPrime + even < 2*kPrime because |even| < kPrime, by the invariants
                // of that structure. Thus kPrime + even - odd < 2*kPrime because odd >=
                // 0, because it's unsigned and less than kPrime. Lastly step_root <
                // kPrime, because |kNTTRootsMontgomery| is static data.
                s->coeff[j + offset] = reduce_montgomery((uint64_t)step_root *
                                                     (uint64_t)(ML_DSA_Q + even - odd));
            }
            k += 2 * offset;
        }
    }
    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        s->coeff[i] = reduce_montgomery((uint64_t)s->coeff[i] *
                                        (uint64_t)kInverseDegreeMontgomery);
}
