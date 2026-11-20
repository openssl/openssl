/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "internal/safe_math.h"
#include "crypto/cryptlib.h"
#include "crypto/fsnerr.h"
#include "../bn/bn_local.h" /* For using the low level bignum functions */
#include "fsn_local.h"

OSSL_SAFE_MATH_MULU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

size_t OSSL_FSN_sqr_ctx_size_from_sizes(size_t r_dsize, size_t a_dsize)
{
    size_t max, limbs, n_numbers = 1;
    int err = 0;

    max = safe_mul_size_t(2, a_dsize, &err);
    if (r_dsize < max)
        n_numbers++;
    limbs = safe_mul_size_t(n_numbers, max, &err);

    return err == 0 ? OSSL_FSN_CTX_size(1, n_numbers, limbs) : 0;
}

size_t OSSL_FSN_sqr_ctx_size_from_nums(const OSSL_FSN *r, const OSSL_FSN *a)
{
    if (r == NULL || a == NULL)
        return 0;

    return OSSL_FSN_sqr_ctx_size_from_sizes(r->dsize, a->dsize);
}

int OSSL_FSN_sqr(OSSL_FSN *r, const OSSL_FSN *a, OSSL_FSN_CTX *ctx)
{
    if (ossl_unlikely(r == NULL || a == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FSN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    const void *token = OSSL_FSN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    size_t al = (size_t)a->dsize;
    size_t rl = (size_t)r->dsize;
    size_t max = (size_t)(2 * al);

    int ret = 0;
#ifdef BN_SQR_COMBA
    if (al == 4 && rl >= 8) {
        bn_sqr_comba4(r->d, a->d);
        goto end;
    } else if (al == 8 && rl >= 16) {
        bn_sqr_comba8(r->d, a->d);
        goto end;
    }
#endif

    /* rl < max is always true when r == a, so covers that case too */
    OSSL_FSN *rr = r;
    if (rl < max)
        if ((rr = OSSL_FSN_CTX_get_limbs(ctx, token, max)) == NULL)
            goto err;

    OSSL_FSN *tmp = NULL;
    if ((tmp = OSSL_FSN_CTX_get_limbs(ctx, token, max)) == NULL)
        goto err;

    if (al != 0)
        bn_sqr_normal(rr->d, a->d, (int)al, tmp->d);

    if (rr != r) {
        /*
         * We use OSSL_FSN_copy_truncate() here, because OSSL_FSN_copy() expects
         * to make a full copy, but r may be smaller than rr
         */
        OSSL_FSN_copy_truncate(r, rr);
    }

#ifdef BN_SQR_COMBA
end:
#endif

    ret = 1;

    /* Zeroise everything above the result, if the r is that large */
    size_t dif = (rl > max) ? rl - max : 0;
    OSSL_FSN_ULONG *rp = &r->d[max];
    while (dif > 0) {
        *rp++ = 0;
        dif--;
    }

err:
    OSSL_FSN_CTX_end(ctx, token);
    return ret;
}
