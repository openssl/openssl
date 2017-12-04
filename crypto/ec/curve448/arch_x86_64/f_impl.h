/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2014-2016 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#define GF_HEADROOM 60
#define FIELD_LITERAL(a,b,c,d,e,f,g,h) {{a,b,c,d,e,f,g,h}}
#define LIMB_PLACE_VALUE(i) 56

void gf_add_RAW(gf out, const gf a, const gf b)
{
    for (unsigned int i = 0; i < sizeof(*out) / sizeof(uint64xn_t); i++) {
        ((uint64xn_t *) out)[i] =
            ((const uint64xn_t *)a)[i] + ((const uint64xn_t *)b)[i];
    }
}

void gf_sub_RAW(gf out, const gf a, const gf b)
{
    for (unsigned int i = 0; i < sizeof(*out) / sizeof(uint64xn_t); i++) {
        ((uint64xn_t *) out)[i] =
            ((const uint64xn_t *)a)[i] - ((const uint64xn_t *)b)[i];
    }
}

void gf_bias(gf a, int amt)
{
    uint64_t co1 = ((1ull << 56) - 1) * amt, co2 = co1 - amt;

#if __AVX2__
    uint64x4_t lo = { co1, co1, co1, co1 }, hi = {
    co2, co1, co1, co1};
    uint64x4_t *aa = (uint64x4_t *) a;
    aa[0] += lo;
    aa[1] += hi;
#elif __SSE2__
    uint64x2_t lo = { co1, co1 }, hi = {
    co2, co1};
    uint64x2_t *aa = (uint64x2_t *) a;
    aa[0] += lo;
    aa[1] += lo;
    aa[2] += hi;
    aa[3] += lo;
#else
    for (unsigned int i = 0; i < sizeof(*a) / sizeof(uint64_t); i++) {
        a->limb[i] += (i == 4) ? co2 : co1;
    }
#endif
}

void gf_weak_reduce(gf a)
{
    /* PERF: use pshufb/palignr if anyone cares about speed of this */
    uint64_t mask = (1ull << 56) - 1;
    uint64_t tmp = a->limb[7] >> 56;

    a->limb[4] += tmp;
    for (unsigned int i = 7; i > 0; i--) {
        a->limb[i] = (a->limb[i] & mask) + (a->limb[i - 1] >> 56);
    }
    a->limb[0] = (a->limb[0] & mask) + tmp;
}
