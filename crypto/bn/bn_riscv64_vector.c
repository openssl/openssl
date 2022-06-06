/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdint.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "bn_local.h"

void bn_mul_mont_rv64imv_zvl128b_sew32_bn256_nelement20(
        uint32_t* r, const uint32_t* a, const uint32_t* b, const uint32_t* p, const uint32_t mu);

void bn_mul_mont_rv64imv_zvl128b_sew32_bn4096_nelement260(
        uint32_t* r, const uint32_t* a, const uint32_t* b, const uint32_t* p, const uint32_t mu);

int bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0, int num)
{
    //printf("!: ");
    //for(int i = 0 ; i != num; i ++)
    //    printf("%lx ", ap[i]);
    //printf("\n");
    //for(int i = 0 ; i != num; i ++)
    //    printf("%lx ", bp[i]);
    //printf("\n");
    //for(int i = 0 ; i != num; i ++)
    //    printf("%lx ", np[i]);
    //printf("\n");

    // prepare input for rvv
    // 20 comes from 256/16 + 4, where 16 = sew (32) / 2, 4 = vlen(128) / sew(32)
    // 260 comes from 4096/16 + 4
    // NOT SECURE!!!! only for demo
    uint32_t AB[260] = {0};
    uint32_t A[260] = {0};
    uint32_t B[260] = {0};
    uint32_t N[260] = {0};

    BN_ULONG ta, tb, tn;
    for(int i = 0; i != num; ++i) {
        ta = ap[i];
        tb = bp[i];
        tn = np[i];
        // 64 bit (BN_ULONG) into 4 uint32_t
        for(int j = 0; j != BN_BYTES/2; ++j) {
            A[i* (BN_BYTES/2) + j] = ta & 0xffff;
            B[i* (BN_BYTES/2) + j] = tb & 0xffff;
            N[i* (BN_BYTES/2) + j] = tn & 0xffff;
            ta >>= 16;
            tb >>= 16;
            tn >>= 16;
        }
    }
    
    // number of 16-bit words in A, B and N
    if (num*(BN_BYTES/2) <= 16)
        bn_mul_mont_rv64imv_zvl128b_sew32_bn256_nelement20(AB, A, B, N, n0[0] & 0xffff);
    else
        bn_mul_mont_rv64imv_zvl128b_sew32_bn4096_nelement260(AB, A, B, N, n0[0] & 0xffff);
    // 256 and 4096 are just two demo here
    // we can generate any bn{x} in mmm_mem.pl

    // convert rvv output to BN format
    for(int i = 0; i != num; ++i) {
        tn = 0;
        for(int j = 0; j != BN_BYTES/2; ++j) {
            tn <<= 16;
            tn |= AB[i* (BN_BYTES/2) + BN_BYTES/2 - 1 - j];
        }
        rp[i] = tn;
    }

    // conditional subtraction as rp is now in Z/2NZ
    // NOTE: this is not constant time!
    int bigger = 0;
    for(int i = num - 1; i >= 0; --i) {
        if (rp[i] > np[i]) {
            bigger = 1;
            break;
        } else if (rp[i] < np[i])
            break;
        // equal then next iteration
    }
    // carry that should be in rp[num] (out of bound, of course)
    if (AB[num * (BN_BYTES/2)] != 0 || bigger) {
        bn_sub_words(rp, rp, np, num);
    }

    //for(int i = 0 ; i != num; i ++)
    //    printf("%lx ", rp[i]);
    //printf("\n\n");

    // need to memzero A, B, AB and N!
    return 1;
}
