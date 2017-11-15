/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "f_field.h"

void gf_mul (gf_s *__restrict__ cs, const gf as, const gf bs) {
    const uint64_t *a = as->limb, *b = bs->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum1 = 0, accum2;
    uint64_t mask = (1ull<<56) - 1;  

    uint64_t aa[4] VECTOR_ALIGNED, bb[4] VECTOR_ALIGNED, bbb[4] VECTOR_ALIGNED;

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i=0; i<sizeof(aa)/sizeof(uint64xn_t); i++) {
        ((uint64xn_t*)aa)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)(&a[4]))[i];
        ((uint64xn_t*)bb)[i] = ((const uint64xn_t*)b)[i] + ((const uint64xn_t*)(&b[4]))[i]; 
        ((uint64xn_t*)bbb)[i] = ((const uint64xn_t*)bb)[i] + ((const uint64xn_t*)(&b[4]))[i];     
    }
    /*
    for (int i=0; i<4; i++) {
    aa[i] = a[i] + a[i+4];
    bb[i] = b[i] + b[i+4];
    }
    */

    accum2  = widemul(&a[0],&b[3]);
    accum0  = widemul(&aa[0],&bb[3]);
    accum1  = widemul(&a[4],&b[7]);

    mac(&accum2, &a[1], &b[2]);
    mac(&accum0, &aa[1], &bb[2]);
    mac(&accum1, &a[5], &b[6]);

    mac(&accum2, &a[2], &b[1]);
    mac(&accum0, &aa[2], &bb[1]);
    mac(&accum1, &a[6], &b[5]);

    mac(&accum2, &a[3], &b[0]);
    mac(&accum0, &aa[3], &bb[0]);
    mac(&accum1, &a[7], &b[4]);

    accum0 -= accum2;
    accum1 += accum2;

    c[3] = ((uint64_t)(accum1)) & mask;
    c[7] = ((uint64_t)(accum0)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;
    
    mac(&accum0, &aa[1],&bb[3]);
    mac(&accum1, &a[5], &b[7]);
    mac(&accum0, &aa[2], &bb[2]);
    mac(&accum1, &a[6], &b[6]);
    mac(&accum0, &aa[3], &bb[1]);
    accum1 += accum0;

    accum2 = widemul(&a[0],&b[0]);
    accum1 -= accum2;
    accum0 += accum2;
    
    msb(&accum0, &a[1], &b[3]);
    msb(&accum0, &a[2], &b[2]);
    mac(&accum1, &a[7], &b[5]);
    msb(&accum0, &a[3], &b[1]);
    mac(&accum1, &aa[0], &bb[0]);
    mac(&accum0, &a[4], &b[4]);

    c[0] = ((uint64_t)(accum0)) & mask;
    c[4] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(&a[2],&b[7]);
    mac(&accum0, &a[6], &bb[3]);
    mac(&accum1, &aa[2], &bbb[3]);

    mac(&accum2, &a[3], &b[6]);
    mac(&accum0, &a[7], &bb[2]);
    mac(&accum1, &aa[3], &bbb[2]);

    mac(&accum2, &a[0],&b[1]);
    mac(&accum1, &aa[0], &bb[1]);
    mac(&accum0, &a[4], &b[5]);

    mac(&accum2, &a[1], &b[0]);
    mac(&accum1, &aa[1], &bb[0]);
    mac(&accum0, &a[5], &b[4]);

    accum1 -= accum2;
    accum0 += accum2;

    c[1] = ((uint64_t)(accum0)) & mask;
    c[5] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(&a[3],&b[7]);
    mac(&accum0, &a[7], &bb[3]);
    mac(&accum1, &aa[3], &bbb[3]);

    mac(&accum2, &a[0],&b[2]);
    mac(&accum1, &aa[0], &bb[2]);
    mac(&accum0, &a[4], &b[6]);

    mac(&accum2, &a[1], &b[1]);
    mac(&accum1, &aa[1], &bb[1]);
    mac(&accum0, &a[5], &b[5]);

    mac(&accum2, &a[2], &b[0]);
    mac(&accum1, &aa[2], &bb[0]);
    mac(&accum0, &a[6], &b[4]);

    accum1 -= accum2;
    accum0 += accum2;

    c[2] = ((uint64_t)(accum0)) & mask;
    c[6] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum0 += c[3];
    accum1 += c[7];
    c[3] = ((uint64_t)(accum0)) & mask;
    c[7] = ((uint64_t)(accum1)) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    accum0 >>= 56;
    accum1 >>= 56;
    c[4] += ((uint64_t)(accum0)) + ((uint64_t)(accum1));
    c[0] += ((uint64_t)(accum1));
}

void gf_mulw_unsigned (gf_s *__restrict__ cs, const gf as, uint32_t b) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0, accum4;
    uint64_t mask = (1ull<<56) - 1;  

    accum0 = widemul_rm(b, &a[0]);
    accum4 = widemul_rm(b, &a[4]);

    c[0] = accum0 & mask; accum0 >>= 56;
    c[4] = accum4 & mask; accum4 >>= 56;

    mac_rm(&accum0, b, &a[1]);
    mac_rm(&accum4, b, &a[5]);

    c[1] = accum0 & mask; accum0 >>= 56;
    c[5] = accum4 & mask; accum4 >>= 56;

    mac_rm(&accum0, b, &a[2]);
    mac_rm(&accum4, b, &a[6]);

    c[2] = accum0 & mask; accum0 >>= 56;
    c[6] = accum4 & mask; accum4 >>= 56;

    mac_rm(&accum0, b, &a[3]);
    mac_rm(&accum4, b, &a[7]);

    c[3] = accum0 & mask; accum0 >>= 56;
    c[7] = accum4 & mask; accum4 >>= 56;
    
    accum0 += accum4 + c[4];
    c[4] = accum0 & mask;
    c[5] += accum0 >> 56;

    accum4 += c[0];
    c[0] = accum4 & mask;
    c[1] += accum4 >> 56;
}

void gf_sqr (gf_s *__restrict__ cs, const gf as) {
    const uint64_t *a = as->limb;
    uint64_t *c = cs->limb;

    __uint128_t accum0 = 0, accum1 = 0, accum2;
    uint64_t mask = (1ull<<56) - 1;  

    uint64_t aa[4] VECTOR_ALIGNED;

    /* For some reason clang doesn't vectorize this without prompting? */
    unsigned int i;
    for (i=0; i<sizeof(aa)/sizeof(uint64xn_t); i++) {
      ((uint64xn_t*)aa)[i] = ((const uint64xn_t*)a)[i] + ((const uint64xn_t*)(&a[4]))[i];
    }

    accum2  = widemul(&a[0],&a[3]);
    accum0  = widemul(&aa[0],&aa[3]);
    accum1  = widemul(&a[4],&a[7]);

    mac(&accum2, &a[1], &a[2]);
    mac(&accum0, &aa[1], &aa[2]);
    mac(&accum1, &a[5], &a[6]);

    accum0 -= accum2;
    accum1 += accum2;

    c[3] = ((uint64_t)(accum1))<<1 & mask;
    c[7] = ((uint64_t)(accum0))<<1 & mask;

    accum0 >>= 55;
    accum1 >>= 55;

    mac2(&accum0, &aa[1],&aa[3]);
    mac2(&accum1, &a[5], &a[7]);
    mac(&accum0, &aa[2], &aa[2]);
    accum1 += accum0;

    msb2(&accum0, &a[1], &a[3]);
    mac(&accum1, &a[6], &a[6]);
    
    accum2 = widemul(&a[0],&a[0]);
    accum1 -= accum2;
    accum0 += accum2;

    msb(&accum0, &a[2], &a[2]);
    mac(&accum1, &aa[0], &aa[0]);
    mac(&accum0, &a[4], &a[4]);

    c[0] = ((uint64_t)(accum0)) & mask;
    c[4] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul2(&aa[2],&aa[3]);
    msb2(&accum0, &a[2], &a[3]);
    mac2(&accum1, &a[6], &a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul2(&a[0],&a[1]);
    mac2(&accum1, &aa[0], &aa[1]);
    mac2(&accum0, &a[4], &a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[1] = ((uint64_t)(accum0)) & mask;
    c[5] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum2  = widemul(&aa[3],&aa[3]);
    msb(&accum0, &a[3], &a[3]);
    mac(&accum1, &a[7], &a[7]);

    accum1 += accum2;
    accum0 += accum2;

    accum2  = widemul2(&a[0],&a[2]);
    mac2(&accum1, &aa[0], &aa[2]);
    mac2(&accum0, &a[4], &a[6]);

    mac(&accum2, &a[1], &a[1]);
    mac(&accum1, &aa[1], &aa[1]);
    mac(&accum0, &a[5], &a[5]);

    accum1 -= accum2;
    accum0 += accum2;

    c[2] = ((uint64_t)(accum0)) & mask;
    c[6] = ((uint64_t)(accum1)) & mask;

    accum0 >>= 56;
    accum1 >>= 56;

    accum0 += c[3];
    accum1 += c[7];
    c[3] = ((uint64_t)(accum0)) & mask;
    c[7] = ((uint64_t)(accum1)) & mask;

    /* we could almost stop here, but it wouldn't be stable, so... */

    accum0 >>= 56;
    accum1 >>= 56;
    c[4] += ((uint64_t)(accum0)) + ((uint64_t)(accum1));
    c[0] += ((uint64_t)(accum1));
}
