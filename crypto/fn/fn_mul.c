/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/err.h>
#include "crypto/cryptlib.h"
#include "crypto/fnerr.h"
#include "../bn/bn_local.h" /* For using the low level bignum functions */
#include "fn_local.h"

size_t OSSL_FN_mul_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b)
{
    size_t limbs = 0;

    if (r == NULL || a == NULL || b == NULL)
        return 0;
    if (r == a || r == b)
        limbs = r->dsize;

    return OSSL_FN_CTX_size(1, limbs == 0 ? 0 : 1, limbs);
}

int OSSL_FN_mul(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b, OSSL_FN_CTX *ctx)
{
    size_t al = (size_t)a->dsize;
    size_t bl = (size_t)b->dsize;
    size_t rl = (size_t)r->dsize;
    size_t max = (size_t)(al + bl);
    const void *token = OSSL_FN_CTX_start(ctx);
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

    OSSL_FN *rr = r;
    if ((r == a) || (r == b))
        if ((rr = OSSL_FN_CTX_get_limbs(ctx, rl)) == NULL)
            goto err;

    bn_mul_truncated(rr->d, (int)rl, a->d, (int)al, b->d, (int)bl);

    if (rr != r)
        if (OSSL_FN_copy(r, rr) == NULL)
            goto err;

#ifdef BN_MUL_COMBA
end:
#endif

{
    size_t dif = (rl > max) ? rl - max : 0;
    OSSL_FN_ULONG *rp = &r->d[max];
    while (dif > 0) {
        *rp++ = 0;
        dif--;
    }
}

    ret = 1;
err:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
