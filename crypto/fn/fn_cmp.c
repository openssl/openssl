/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/fn.h"
#include "../bn/bn_local.h"         /* For using the low level bignum functions */
#include "fn_local.h"

/* This must be placed last, 'cause it depends on BN_ULONG being defined */
#include "internal/constant_time.h"

int OSSL_FN_ucmp(const OSSL_FN *a, const OSSL_FN *b)
{
    const OSSL_FN_ULONG *ap = a->d;
    const OSSL_FN_ULONG *bp = b->d;
    /* The larger array, will be partially compared with zero */
    const OSSL_FN_ULONG *zp = NULL;
    size_t min, max;

    if (a->dsize > b->dsize) {
        min = b->dsize;
        max = a->dsize;
        zp = ap;
    } else {
        min = a->dsize;
        max = b->dsize;
        zp = bp;
    }

    int res = 0;
    for (size_t i = 0; i < min; i++) {
        res = constant_time_select_int((int)constant_time_lt_bn(ap[i], bp[i]), -1, res);
        res = constant_time_select_int((int)constant_time_lt_bn(bp[i], ap[i]), 1, res);
    }
    for (size_t i = min; i < max; i++) {
        /* zp[i] will never be smaller than zero, so we only check if it's larger */
        res = constant_time_select_int((int)constant_time_lt_bn(0, zp[i]), 1, res);
    }
    return res;
}

int OSSL_FN_cmp(const OSSL_FN *a, const OSSL_FN *b)
{
    if (a->is_negative != b->is_negative)
        /*
         * a->is_negative == 0 && b->negative == 1  =>  1 - 0  =>   1
         * a->is_negative == 1 && b->negative == 0  =>  0 - 1  =>  -1
         */
        return !a->is_negative - !b->is_negative;

    /* If the numbers are negative, the unsigned comparison result must be negated */
    int cmp_factor = (a->is_negative) ? -1 : 1;

    return OSSL_FN_ucmp(a, b) * cmp_factor;
}
