/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
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
    int ret = bn_mul_fixed_top(r, a, b, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

int bn_mul_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    int top, al, bl;
    BIGNUM *rr;
#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
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

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
    i = al - bl;
#endif
#ifdef BN_MUL_COMBA
    if (i == 0) {
# if 0
        if (al == 4) {
            if (bn_wexpand(rr, 8) == NULL)
                goto err;
            rr->flags |= BN_FLG_FIXED_TOP;
            bn_set_top(rr, 8);
            bn_mul_comba4(rr->d, a->d, b->d);
            goto end;
        }
# endif
        if (al == 8) {
            if (bn_wexpand(rr, 16) == NULL)
                goto err;
            rr->flags |= BN_FLG_FIXED_TOP;
            bn_set_top(rr, 16);
            bn_mul_comba8(rr->d, a->d, b->d);
            goto end;
        }
    }
#endif                          /* BN_MUL_COMBA */
#ifdef BN_RECURSION
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
            } else {            /* al <= j || bl <= j */
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
#endif                          /* BN_RECURSION */
    if (bn_wexpand(rr, top) == NULL)
        goto err;
    bn_set_top(rr, top);
    bn_mul_normal(rr->d, a->d, al, b->d, bl);

#if defined(BN_MUL_COMBA) || defined(BN_RECURSION)
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
