/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
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

int OSSL_FN_sqr(OSSL_FN *r, const OSSL_FN *a, OSSL_FN_CTX *ctx)
{
    if (!OSSL_FN_CTX_start(ctx))
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
    OSSL_FN *rr = r;
    if (rl < max)
        if ((rr = OSSL_FN_CTX_get_limbs(ctx, max)) == NULL)
            goto err;

    OSSL_FN *tmp = NULL;
    if ((tmp = OSSL_FN_CTX_get_limbs(ctx, max)) == NULL)
        goto err;

    if (al != 0)
        bn_sqr_normal(rr->d, a->d, (int)al, tmp->d);

    if (rr != r) {
        /*
         * We use OSSL_FN_copy_truncate() here, because OSSL_FN_copy() expects
         * to make a full copy, but r may be smaller than rr
         */
        OSSL_FN_copy_truncate(r, rr);
    }

#ifdef BN_SQR_COMBA
end:
#endif

    ret = 1;

    /* Zeroise everything above the result, if the r is that large */
    size_t dif = (rl > max) ? rl - max : 0;
    OSSL_FN_ULONG *rp = &r->d[max];
    while (dif > 0) {
        *rp++ = 0;
        dif--;
    }

err:
    OSSL_FN_CTX_end(ctx);
    return ret;
}
