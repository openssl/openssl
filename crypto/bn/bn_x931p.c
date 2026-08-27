/*
 * Copyright 2011-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <openssl/bn.h>
#include "bn_local.h"
#include "crypto/fn.h"

/* X9.31 routines for prime derivation */

/*
 * This is the main X9.31 prime derivation function. From parameters Xp1, Xp2
 * and Xp derive the prime p. If the parameters p1 or p2 are not NULL they
 * will be returned too: this is needed for testing.
 */

int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx,
    BN_GENCB *cb)
{
    int ret = 0, limbs;
    OSSL_FN *fn_p, *fn_p1 = NULL, *fn_p2 = NULL;
    OSSL_FN *fn_Xp, *fn_Xp1, *fn_Xp2, *fn_e;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_LIB_CTX *libctx;
    size_t fn_size;

    /* Only odd e supported */
    if (e == NULL || !BN_is_odd(e))
        return 0;
    if (Xp == NULL || Xp1 == NULL || Xp2 == NULL || e == NULL)
        return 0;
    limbs = Xp->data != NULL ? Xp->data->dsize : 0;
    if (limbs == 0)
        return 0;

    if ((fn_p = bn_acquire_ossl_fn(p, limbs)) == NULL)
        return 0;
    if (p1 != NULL && (fn_p1 = bn_acquire_ossl_fn(p1, limbs)) == NULL)
        goto release;
    if (p2 != NULL && (fn_p2 = bn_acquire_ossl_fn(p2, limbs)) == NULL)
        goto release;

    fn_Xp = bn_get_ossl_fn(Xp);
    fn_Xp1 = bn_get_ossl_fn(Xp1);
    fn_Xp2 = bn_get_ossl_fn(Xp2);
    fn_e = bn_get_ossl_fn(e);
    if (fn_Xp == NULL || fn_Xp1 == NULL || fn_Xp2 == NULL || fn_e == NULL)
        goto release;

    libctx = ossl_bn_get_libctx(ctx);
    fn_size = OSSL_FN_X931_derive_prime_ctx_size(fn_p, fn_p1, fn_p2,
        fn_Xp, fn_Xp1, fn_Xp2, fn_e);
    if (fn_size == 0)
        goto release;
    fn_ctx = OSSL_FN_CTX_new_size(libctx, fn_size);
    if (fn_ctx == NULL)
        goto release;

    if (OSSL_FN_X931_derive_prime(fn_p, fn_p1, fn_p2, fn_Xp, fn_Xp1,
            fn_Xp2, fn_e, fn_ctx, cb, libctx))
        ret = 1;

release:
    OSSL_FN_CTX_free(fn_ctx);
    bn_release(p, ret ? limbs : 0);
    if (fn_p1 != NULL)
        bn_release(p1, ret ? limbs : 0);
    if (fn_p2 != NULL)
        bn_release(p2, ret ? limbs : 0);

    return ret;
}

/*
 * Generate pair of parameters Xp, Xq for X9.31 prime generation. Note: nbits
 * parameter is sum of number of bits in both.
 */

int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx)
{
    int per, limbs, ret = 0;
    OSSL_FN *f, *g;
    OSSL_LIB_CTX *libctx;

    /*
     * The OSSL_FN peer checks the same condition; do it here too to
     * derive sane limb sizing before the acquire steps.
     */
    if ((nbits < 1024) || (nbits & 0xff))
        return 0;
    per = nbits >> 1;
    limbs = (per + BN_BITS2 - 1) / BN_BITS2;

    libctx = ossl_bn_get_libctx(ctx);

    if ((f = bn_acquire_ossl_fn(Xp, limbs)) == NULL)
        return 0;
    if ((g = bn_acquire_ossl_fn(Xq, limbs)) == NULL) {
        bn_release(Xp, 0);
        return 0;
    }

    {
        size_t fn_size = OSSL_FN_X931_generate_Xpq_ctx_size(f);
        OSSL_FN_CTX *fn_ctx = NULL;

        if (fn_size != 0)
            fn_ctx = OSSL_FN_CTX_new_size(libctx, fn_size);
        if (fn_ctx != NULL
            && OSSL_FN_X931_generate_Xpq(f, g, nbits, fn_ctx, libctx))
            ret = 1;
        OSSL_FN_CTX_free(fn_ctx);
    }

    bn_release(Xp, ret ? limbs : 0);
    bn_release(Xq, ret ? limbs : 0);

    return ret;
}

/*
 * Generate primes using X9.31 algorithm. Of the values p, p1, p2, Xp1 and
 * Xp2 only 'p' needs to be non-NULL. If any of the others are not NULL the
 * relevant parameter will be stored in it. Due to the fact that |Xp - Xq| >
 * 2^(nbits - 100) must be satisfied Xp and Xq are generated using the
 * previous function and supplied as input.
 */

int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
    BIGNUM *Xp1, BIGNUM *Xp2,
    const BIGNUM *Xp,
    const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb)
{
    int ret = 0, limbs;
    OSSL_FN *fn_p, *fn_p1 = NULL, *fn_p2 = NULL;
    OSSL_FN *fn_Xp1 = NULL, *fn_Xp2 = NULL, *fn_Xp, *fn_e;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_LIB_CTX *libctx;
    size_t fn_size;

    if (Xp == NULL || e == NULL)
        return 0;
    limbs = Xp->data != NULL ? Xp->data->dsize : 0;
    if (limbs == 0)
        return 0;

    if ((fn_p = bn_acquire_ossl_fn(p, limbs)) == NULL)
        return 0;
    if (p1 != NULL && (fn_p1 = bn_acquire_ossl_fn(p1, limbs)) == NULL)
        goto release;
    if (p2 != NULL && (fn_p2 = bn_acquire_ossl_fn(p2, limbs)) == NULL)
        goto release;
    if (Xp1 != NULL && (fn_Xp1 = bn_acquire_ossl_fn(Xp1, limbs)) == NULL)
        goto release;
    if (Xp2 != NULL && (fn_Xp2 = bn_acquire_ossl_fn(Xp2, limbs)) == NULL)
        goto release;

    fn_Xp = bn_get_ossl_fn(Xp);
    fn_e = bn_get_ossl_fn(e);
    if (fn_Xp == NULL || fn_e == NULL)
        goto release;

    libctx = ossl_bn_get_libctx(ctx);
    fn_size = OSSL_FN_X931_generate_prime_ctx_size(fn_p, fn_p1, fn_p2,
        fn_Xp, fn_e);
    if (fn_size == 0)
        goto release;
    fn_ctx = OSSL_FN_CTX_new_size(libctx, fn_size);
    if (fn_ctx == NULL)
        goto release;

    if (OSSL_FN_X931_generate_prime(fn_p, fn_p1, fn_p2, fn_Xp1, fn_Xp2,
            fn_Xp, fn_e, fn_ctx, cb, libctx))
        ret = 1;

release:
    OSSL_FN_CTX_free(fn_ctx);
    bn_release(p, ret ? limbs : 0);
    if (fn_p1 != NULL)
        bn_release(p1, ret ? limbs : 0);
    if (fn_p2 != NULL)
        bn_release(p2, ret ? limbs : 0);
    if (fn_Xp1 != NULL)
        bn_release(Xp1, ret ? limbs : 0);
    if (fn_Xp2 != NULL)
        bn_release(Xp2, ret ? limbs : 0);

    return ret;
}
