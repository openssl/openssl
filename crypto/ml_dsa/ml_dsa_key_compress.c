/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"

/* Rounding & hints */

// FIPS 204, Algorithm 35 (`Power2Round`).
// @returns r1
void ossl_ml_dsa_key_compress_power2_round(uint32_t r, uint32_t *r1, uint32_t *r0)
{
    unsigned int mask;
    uint32_t r0_adjusted, r1_adjusted;

    *r1 = r >> ML_DSA_D_BITS;         /* top bits */
    *r0 = r - (*r1 << ML_DSA_D_BITS); /* bottom 13 bits */
    r0_adjusted = mod_sub(*r0, 1 << ML_DSA_D_BITS);
    r1_adjusted = *r1 + 1;

    // Mask is set iff r0 > (2^(dropped_bits))/2.
    //i.e. we are in the negative left half of the circle
    mask = constant_time_lt((uint32_t)(1 << (ML_DSA_D_BITS - 1)), *r0);
    // r0 = mask ? r0_adjusted : r0
    *r0 = constant_time_select_int(mask, r0_adjusted, *r0);
    // r1 = mask ? r1_adjusted : r1
    *r1 = constant_time_select_int(mask, r1_adjusted, *r1);
}


// FIPS 204, Algorithm 37 (`HighBits`).
uint32_t ossl_ml_dsa_key_compress_high_bits(uint32_t r, uint32_t gamma2)
{
    uint32_t r1;
    // Reference description (given 0 <= r < q):
    //
    // ```
    // int32_t r0 = r mod+- (2 * kGamma2);
    // if (r - r0 == q - 1) {
    //   return 0;
    // } else {
    //   return (r - r0) / (2 * kGamma2);
    // }
    // ```
    //
    // Below is the formula taken from the reference implementation.
    //
    r1 = (r + 127) >> 7;
    if (gamma2 == ML_DSA_Q_MINUS1_DIV32) {
        // Here, gamma2 == 2^18 - 2^8
        // This returns ((ceil(r / 2^7) * (2^10 + 1) + 2^21) / 2^22) mod 2^4
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15; /* mod 16 */
        return r1;
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
        return r1;
    }
}

// FIPS 204, Algorithm 36 (`Decompose`).
void ossl_ml_dsa_key_compress_decompose(uint32_t r, uint32_t gamma2,
                                        uint32_t *r1, int32_t *r0)
{
    *r1 = ossl_ml_dsa_key_compress_high_bits(r, gamma2);

    *r0 = r - *r1 * 2 * (int32_t)gamma2;
    *r0 -= (((int32_t)ML_DSA_Q_MINUS1_DIV2 - *r0) >> 31) & (int32_t)ML_DSA_Q;
}

// FIPS 204, Algorithm 38 (`LowBits`).
int32_t ossl_ml_dsa_key_compress_low_bits(uint32_t r, uint32_t gamma2)
{
    uint32_t r1;
    int32_t r0;

    ossl_ml_dsa_key_compress_decompose(r, gamma2, &r1, &r0);
    return r0;
}

// FIPS 204, Algorithm 39 (`MakeHint`).
//
// In the spec this takes two arguments, z and r, and is called with
//   z = -ct0
//   r = w - cs2 + ct0
//
// It then computes HighBits (algorithm 37) of z and z+r. But z+r is just w -
// cs2, so this takes three arguments and saves an addition.
int32_t ossl_ml_dsa_key_compress_make_hint(uint32_t ct0, uint32_t cs2,
                                           uint32_t gamma2, uint32_t w)
{
    uint32_t r_plus_z = mod_sub(w, cs2);
    uint32_t r = reduce_once(r_plus_z + ct0);

    return  ossl_ml_dsa_key_compress_high_bits(r, gamma2)
        !=  ossl_ml_dsa_key_compress_high_bits(r_plus_z, gamma2);
}

// FIPS 204, Algorithm 40 (`UseHint`).
// This is not constant time
uint32_t ossl_ml_dsa_key_compress_use_hint(uint32_t hint, uint32_t r,
                                           uint32_t gamma2)
{
    uint32_t r1;
    int32_t r0;

    ossl_ml_dsa_key_compress_decompose(r, gamma2, &r1, &r0);

    if (hint == 0)
        return r1;

    if (gamma2 == ((ML_DSA_Q - 1) / 32)) {
        /* m = 16, thus |mod m| in the spec turns into |& 15| */
        return r0 > 0 ? (r1 + 1) & 15 : (r1 - 1) & 15;
    } else {
        /* m = 44 if gamma2 = ((q - 1) / 88) */
        if (r1 > 0)
            return (r1 == 43) ? 0 : r1 + 1;
        else
            return (r1 == 0) ? 43 : r1 - 1;
    }
}
