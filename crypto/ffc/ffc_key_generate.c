/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/ffc.h"
#include "crypto/bn.h"
#include "crypto/fxn.h"

/*
 * SP800-56Ar3 5.6.1.1.4 Key pair generation by testing candidates.
 * Generates a private key in the interval [1, min(2 ^ N - 1, q - 1)].
 *
 * ctx must be set up with a libctx (for fips mode).
 * params contains the FFC domain parameters p, q and g (for DH or DSA).
 * N is the maximum bit length of the generated private key,
 * s is the security strength.
 * priv_key is the returned private key,
 */
int ossl_ffc_generate_private_key(BN_CTX *ctx, const FFC_PARAMS *params,
    int N, int s, BIGNUM *priv)
{
    int ret = 0, qbits = BN_num_bits(params->q), plimbs;
    OSSL_LIB_CTX *libctx = ossl_bn_get_libctx(ctx);
    OSSL_FXN *fxn_priv = NULL, *two_powN = NULL;
    const OSSL_FXN *fxn_q = NULL, *fxn_m;

    /* Deal with the edge cases where the value of N and/or s is not set */
    if (s == 0)
        return 0;
    if (N == 0)
        N = params->keylength ? params->keylength : 2 * s;

    /* Step (2) : check range of N */
    if (N < 2 * s || N > qbits)
        return 0;

    /* Candidates and two_powN may reach 2^N, i.e. N + 1 bits */
    plimbs = (N + BN_BITS2) / BN_BITS2;

    if ((fxn_q = bn_get_ossl_fxn(params->q)) == NULL)
        return 0;

    /*
     * Acquire the writable result first.  The generation loop below exits
     * only when fxn_priv < fxn_m <= 2^N, so the generated key has at most N
     * significant bits and always fits in the acquired width; that width
     * is therefore the bn_release() width as well.
     */
    if ((fxn_priv = bn_acquire_ossl_fxn(priv, plimbs)) == NULL)
        return 0;
    if ((two_powN = OSSL_FXN_new_limbs(plimbs)) == NULL)
        goto err;

    /* Step (5) : M = min(2 ^ N, q) */
    if (!OSSL_FXN_one(two_powN) || !OSSL_FXN_lshift(two_powN, two_powN, N))
        goto err;
    fxn_m = (OSSL_FXN_cmp(two_powN, fxn_q) > 0) ? fxn_q : two_powN;

    do {
        /* Steps (3, 4 & 7) :  c + 1 = 1 + random[0..2^N - 1] */
        if (!OSSL_FXN_priv_rand_range(fxn_priv, two_powN, 0, libctx)
            || !OSSL_FXN_add_word(fxn_priv, 1))
            goto err;
        /* Step (6) : loop if c > M - 2 (i.e. c + 1 >= M) */
        if (OSSL_FXN_cmp(fxn_priv, fxn_m) < 0)
            break;
    } while (1);

    ret = 1;
err:
    bn_release(priv, plimbs);
    OSSL_FXN_free(two_powN);
    return ret;
}
