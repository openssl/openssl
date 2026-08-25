/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "internal/mem_alloc_utils.h"
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * Generate the initial values of Xp and Xq, to be used for further
 * derivation of primes p and q.  The |Xp - Xq| > 2^(nbits - 100)
 * requirement ensures the pair is not accidentally close.
 */
static int ossl_fn_x931_generate_Xpq_int(OSSL_FN *dst, OSSL_FN *oth,
    int nbits, OSSL_FN_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    OSSL_FN *bigger, *smaller, *t;
    const void *token;
    int i, ret = 0;

    if ((token = OSSL_FN_CTX_start(ctx)) == NULL)
        return 0;
    t = OSSL_FN_CTX_get_limbs(ctx, (size_t)dst->dsize);
    if (t == NULL)
        goto err;

    if (!OSSL_FN_priv_rand(dst, nbits, OSSL_FN_RAND_TOP_TWO,
            OSSL_FN_RAND_BOTTOM_ANY, 0, libctx))
        goto err;

    for (i = 0; i < 1000; i++) {
        if (!OSSL_FN_priv_rand(oth, nbits, OSSL_FN_RAND_TOP_TWO,
                OSSL_FN_RAND_BOTTOM_ANY, 0, libctx))
            goto err;

        bigger = dst;
        smaller = oth;
        if (OSSL_FN_cmp(dst, oth) < 0) {
            bigger = oth;
            smaller = dst;
        }

        if (!OSSL_FN_sub(t, bigger, smaller))
            goto err;
        if (OSSL_FN_num_bits(t) > (size_t)(nbits - 100)) {
            ret = 1;
            goto err;
        }
    }

err:
    if (!OSSL_FN_CTX_end(ctx, token))
        ret = 0;
    return ret;
}

int OSSL_FN_X931_generate_Xpq(OSSL_FN *Xp, OSSL_FN *Xq, int nbits,
    OSSL_FN_CTX *ctx, OSSL_LIB_CTX *libctx)
{
    /* 512+128s shape check, sized as the sum of both Xp and Xq */
    if ((nbits < 1024) || (nbits & 0xff)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_RANGE);
        return 0;
    }
    nbits >>= 1;

    return ossl_fn_x931_generate_Xpq_int(Xp, Xq, nbits, ctx, libctx);
}

/* The usual static helpers from the other fn_*.c operation files. */
static size_t ctx_add_size(size_t a, size_t b)
{
    int err = 0;
    size_t r = safe_add_size_t(a, b, &err);

    return err == 0 ? r : 0;
}

static size_t ctx_max_size(size_t a, size_t b)
{
    return a > b ? a : b;
}

/*
 * Estimate the arena payload for OSSL_FN_X931_generate_Xpq().  The
 * operation holds one scratch number of the destination's width for
 * the pair gap check.
 */
size_t OSSL_FN_X931_generate_Xpq_ctx_size(const OSSL_FN *Xp)
{
    if (Xp == NULL || Xp->dsize == 0)
        return 0;

    return OSSL_FN_CTX_size(1, 1, (size_t)Xp->dsize);
}

/*
 * Estimate the arena payload for one embedded primality test on a
 * candidate of width |n| limbs.
 */
