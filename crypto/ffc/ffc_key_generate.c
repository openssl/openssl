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
#include "crypto/fn.h"

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
    BIGNUM *two_powN = NULL;
    OSSL_FN *fn_priv = NULL, *fn_two_powN = NULL;
    const OSSL_FN *fn_q = NULL, *fn_m;

    /* Deal with the edge cases where the value of N and/or s is not set */
    if (s == 0)
        goto err;
    if (N == 0)
        N = params->keylength ? params->keylength : 2 * s;

    /* Step (2) : check range of N */
    if (N < 2 * s || N > qbits)
        return 0;

    plimbs = (N + BN_BITS2 - 1) / BN_BITS2;

    if ((fn_q = bn_get_ossl_fn(params->q)) == NULL)
        goto err;

    /*
     * Acquire the writable values first; the release limb count is derived
     * from the generated value's significance at the end.  two_powN must
     * hold 2^N, i.e. N + 1 bits, hence the extra limb budget.
     */
    if ((fn_priv = bn_acquire_ossl_fn(priv, plimbs + 1)) == NULL)
        goto err;
    if ((two_powN = BN_new()) == NULL
        || (fn_two_powN = bn_acquire_ossl_fn(two_powN, plimbs + 1)) == NULL)
        goto err;

    /* Step (5) : M = min(2 ^ N, q) */
    if (!OSSL_FN_one(fn_two_powN) || !OSSL_FN_lshift(fn_two_powN, fn_two_powN, N))
        goto err;
    fn_m = (OSSL_FN_cmp(fn_two_powN, fn_q) > 0) ? fn_q : fn_two_powN;

    do {
        /* Steps (3, 4 & 7) :  c + 1 = 1 + random[0..2^N - 1] */
        if (!OSSL_FN_priv_rand_range(fn_priv, fn_two_powN, 0, libctx)
            || !OSSL_FN_add_word(fn_priv, 1))
            goto err;
        /* Step (6) : loop if c > M - 2 (i.e. c + 1 >= M) */
        if (OSSL_FN_cmp(fn_priv, fn_m) < 0)
            break;
    } while (1);

    {
        int fn_bits = (int)OSSL_FN_num_bits(fn_priv);

        bn_release(priv, fn_bits > 0 ? (fn_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    }
    bn_release(two_powN, plimbs + 1);
    ret = 1;
err:
    BN_free(two_powN);
    return ret;
}
