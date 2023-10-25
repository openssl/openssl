/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/rand.h"
#include "internal/common.h"

/*
 * Implementation an optimal random integer in a range function.
 * Refer: https://github.com/apple/swift/pull/39143 for a description
 * of the algorithm.
 */
uint32_t ossl_rand_uniform_uint32(OSSL_LIB_CTX *ctx, uint32_t upper, int *err)
{
    uint32_t i, f;      /* integer and fractional parts */
    uint32_t f2, rand;  /* extra fractional part and random material */
    uint64_t prod;      /* temporary holding double width product */
    const int max_followup_iterations = 10;
    int j;

    if (!ossl_assert(upper > 0)) {
        *err = 0;
        return 0;
    }
    if (unlikely(upper == 1))
        return 0;
    /* Get 32 bits of entropy */
    if (RAND_bytes_ex(ctx, (unsigned char *)&rand, sizeof(rand), 0) <= 0) {
        *err = 1;
        return 0;
    }
    prod = (uint64_t)upper * rand;
    i = prod >> 32;
    f = prod & 0xffffffff;
    if (likely(f <= 1 + ~upper))    /* 1+~upper == -upper but compilers whine */
        return i;

    for (j = 0; j < max_followup_iterations; j++) {
        if (RAND_bytes_ex(ctx, (unsigned char *)&rand, sizeof(rand), 0) <= 0) {
            *err = 1;
            return 0;
        }
        prod = (uint64_t)upper * rand;
        f2 = prod >> 32;
        f += f2;
        /* On overflow, add the carry to our result */
        if (f < f2)
            return i + 1;
        /* For not all 1 bits, there is no carry so return the result */
        if (unlikely(f != 0xffffffff))
            return i;
        /* setup for the next word of randomness */
        f = prod & 0xffffffff;
    }
    /*
     * If we get here, we've consumed 32 * max_followup_iterations + 32 bits
     * with no firm decision, this gives a bias with probability < 2^(32*n),
     * likely acceptable.
     */
    return i;
}

uint32_t ossl_rand_range_uint32(OSSL_LIB_CTX *ctx, uint32_t lower, uint32_t upper,
                                int *err)
{
    if (!ossl_assert(lower < upper)) {
        *err = 1;
        return 0;
    }
    return lower + ossl_rand_uniform_uint32(ctx, upper - lower, err);
}
