/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "crypto/cryptlib.h"
#include "crypto/fxnerr.h"
#include "../bn/bn_local.h" /* For using the low level bignum functions */
#include "fxn_local.h"

size_t OSSL_FXN_mul_ctx_size_from_sizes(size_t r_dsize, size_t a_dsize,
    size_t b_dsize)
{
    /*
     * The operands are not at hand, so whether |r| aliases |a| or |b| is
     * unknown.  Budget the aliased case whenever the widths allow it.
     */
    size_t limbs = (r_dsize == a_dsize || r_dsize == b_dsize) ? r_dsize : 0;

    return OSSL_FXN_CTX_size(1, limbs == 0 ? 0 : 1, limbs);
}

size_t OSSL_FXN_mul_ctx_size_from_nums(const OSSL_FXN *r, const OSSL_FXN *a,
    const OSSL_FXN *b)
{
    size_t limbs = 0;

    if (r != NULL && (r == a || r == b))
        limbs = r->dsize;

    return OSSL_FXN_CTX_size(1, limbs == 0 ? 0 : 1, limbs);
}

int OSSL_FXN_mul(OSSL_FXN *r, const OSSL_FXN *a, const OSSL_FXN *b, OSSL_FXN_CTX *ctx)
{
    if (ossl_unlikely(r == NULL || a == NULL || b == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FXN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    size_t al = (size_t)a->dsize;
    size_t bl = (size_t)b->dsize;
    size_t rl = (size_t)r->dsize;
    size_t max = (size_t)(al + bl);
    const void *token = OSSL_FXN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    int ret = 0;
#ifdef BN_MUL_COMBA
    if (al == bl) {
        if (rl >= 16 && al == 8) {
            bn_mul_comba8(r->d, a->d, b->d);
            goto end;
        }
    }
#endif /* BN_MUL_COMBA */

    OSSL_FXN *rr = r;
    if ((r == a) || (r == b))
        if ((rr = OSSL_FXN_CTX_get_limbs(ctx, token, rl)) == NULL)
            goto err;

    bn_mul_truncated(rr->d, (int)rl, a->d, (int)al, b->d, (int)bl);

    if (rr != r)
        if (OSSL_FXN_copy(r, rr) == NULL)
            goto err;

#ifdef BN_MUL_COMBA
end:
#endif

{
    size_t dif = (rl > max) ? rl - max : 0;
    OSSL_FXN_ULONG *rp = &r->d[max];
    while (dif > 0) {
        *rp++ = 0;
        dif--;
    }
}

    ret = 1;
err:
    OSSL_FXN_CTX_end(ctx, token);
    return ret;
}
