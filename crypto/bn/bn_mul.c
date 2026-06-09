/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include "internal/cryptlib.h"
#include "bn_local.h"

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    /* TODO(FIXNUM): TO BE REMOVED */
    if (r->data == NULL || a->data == NULL || b->data == NULL) {
        int ret = bn_mul_fixed_top(r, a, b, ctx);

        bn_correct_top(r);
        bn_check_top(r);

        return ret;
    }

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(r);

    /*
     * Acquiring rf may make r larger.
     * If r == a, then a will also become larger.  Therefore, max must
     * be calculated after rf has been acquired.
     */
    size_t top = a->top + b->top;
    OSSL_FN *rf = bn_acquire_ossl_fn(r, (int)top);

    size_t max = a->dmax + b->dmax;

    OSSL_FN_CTX *fnctx = bn_ctx_acquire_ossl_fn_ctx(ctx, 1, 1, max);
    int ret = OSSL_FN_mul(rf, a->data, b->data, fnctx);
    bn_release(r, (int)top);

    if (ret && !BN_is_zero(r))
        r->neg = a->neg ^ b->neg;

    bn_ctx_release_ossl_fn_ctx(ctx);
    return ret;
}

int bn_mul_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    int top, al, bl;
    BIGNUM *rr;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
    int i;
#endif

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(r);

    al = a->top;
    bl = b->top;

    if ((al == 0) || (bl == 0)) {
        BN_zero(r);
        return 1;
    }
    top = al + bl;

    BN_CTX_start(ctx);
    if ((r == a) || (r == b)) {
        if ((rr = BN_CTX_get(ctx)) == NULL)
            goto err;
    } else
        rr = r;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    i = al - bl;

    if (i == 0) {
#if 0
        if (al == 4) {
            if (bn_wexpand(rr, 8) == NULL)
                goto err;
            rr->flags |= BN_FLG_FIXED_TOP;
            bn_set_top(rr, 8);
            bn_mul_comba4(rr->d, a->d, b->d);
            goto end;
        }
#endif
        if (al == 8) {
            if (bn_wexpand(rr, 16) == NULL)
                goto err;
            rr->flags |= BN_FLG_FIXED_TOP;
            bn_set_top(rr, 16);
            bn_mul_comba8(rr->d, a->d, b->d);
            goto end;
        }
    }

    if ((al >= BN_MULL_SIZE_NORMAL) && (bl >= BN_MULL_SIZE_NORMAL)) {
        if (i >= -1 && i <= 1) {
            BIGNUM *t = NULL;
            int j = 0, k;

            /*
             * Find out the power of two lower or equal to the longest of the
             * two numbers
             */
            if (i >= 0) {
                j = BN_num_bits_word((BN_ULONG)al);
            }
            if (i == -1) {
                j = BN_num_bits_word((BN_ULONG)bl);
            }
            j = 1 << (j - 1);
            assert(j <= al || j <= bl);
            k = j + j;
            t = BN_CTX_get(ctx);
            if (t == NULL)
                goto err;
            if (al > j || bl > j) {
                if (bn_wexpand(t, k * 4) == NULL)
                    goto err;
                t->top = k * 4;
                t->flags |= BN_FLG_FIXED_TOP;
                if (bn_wexpand(rr, k * 4) == NULL)
                    goto err;
                bn_set_top(rr, k * 4);
                rr->flags |= BN_FLG_FIXED_TOP;
                bn_mul_part_recursive(rr->d, a->d, b->d,
                    j, al - j, bl - j, t->d);
            } else { /* al <= j || bl <= j */
                if (bn_wexpand(t, k * 2) == NULL)
                    goto err;
                t->top = k * 2;
                t->flags |= BN_FLG_FIXED_TOP;
                if (bn_wexpand(rr, k * 2) == NULL)
                    goto err;
                bn_set_top(rr, k * 2);
                rr->flags |= BN_FLG_FIXED_TOP;
                bn_mul_recursive(rr->d, a->d, b->d, j, al - j, bl - j, t->d);
            }
            bn_set_top(rr, top);
            goto end;
        }
    }
#endif /* OPENSSL_SMALL_FOOTPRINT */
    if (bn_wexpand(rr, top) == NULL)
        goto err;
    bn_set_top(rr, top);
    bn_mul_normal(rr->d, a->d, al, b->d, bl);

#if !defined(OPENSSL_SMALL_FOOTPRINT)
end:
#endif
    rr->neg = a->neg ^ b->neg;
    rr->flags |= BN_FLG_FIXED_TOP;
    if (r != rr && BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
err:
    bn_check_top(r);
    BN_CTX_end(ctx);
    return ret;
}
