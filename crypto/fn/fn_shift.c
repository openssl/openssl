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
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * In respect to shift factor the execution time is invariant of
 * |n % OSSL_FN_BITS|, but not |n / OSSL_FN_BITS|. Or in other words
 * pre-condition for constant-time-ness is |n < OSSL_FN_BITS| or
 * |n / OSSL_FN_BITS| being non-secret.
 */
int OSSL_FN_lshift(OSSL_FN *r, const OSSL_FN *a, int n)
{
    size_t i, nw;
    unsigned int lb, rb;
    const OSSL_FN_ULONG *ap = a->d;
    OSSL_FN_ULONG *rp = r->d;
    size_t rl = (size_t)r->dsize;
    size_t al = (size_t)a->dsize;

    if (n < 0) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_SHIFT);
        return 0;
    }

    nw = (size_t)n / OSSL_FN_BITS;
    if (nw >= rl) {
        memset(rp, 0, sizeof(*rp) * rl);
        return 1;
    }

    lb = (unsigned int)n % OSSL_FN_BITS;
    rb = OSSL_FN_BITS - lb;

    /*
     * Work from the high end to support r == a.  Each result limb only
     * depends on the corresponding source limb and the limb just below it,
     * neither of which has been overwritten yet when walking downward.
     */
    for (i = rl; i > 0; i--) {
        size_t r_idx = i - 1;
        OSSL_FN_ULONG limb = 0;

        if (r_idx >= nw) {
            size_t src_idx = r_idx - nw;

            if (src_idx < al)
                limb = (ap[src_idx] << lb) & OSSL_FN_MASK;
            if (lb != 0 && src_idx > 0 && src_idx - 1 < al)
                limb |= ap[src_idx - 1] >> rb;
        }
        rp[r_idx] = limb;
    }

    return 1;
}

int OSSL_FN_lshift1(OSSL_FN *r, const OSSL_FN *a)
{
    OSSL_FN_ULONG *rp = r->d;
    const OSSL_FN_ULONG *ap = a->d;
    OSSL_FN_ULONG t, c = 0;
    size_t rl = (size_t)r->dsize;
    size_t al = (size_t)a->dsize;
    size_t l = (rl < al) ? rl : al;
    size_t i;

    for (i = 0; i < l; i++) {
        t = ap[i];
        rp[i] = ((t << 1) | c) & OSSL_FN_MASK;
        c = t >> (OSSL_FN_BITS - 1);
    }

    if (i < rl) {
        rp[i++] = c;
        for (; i < rl; i++)
            rp[i] = 0;
    }

    return 1;
}

/*
 * In respect to shift factor the execution time is invariant of
 * |n % OSSL_FN_BITS|, but not |n / OSSL_FN_BITS|. Or in other words
 * pre-condition for constant-time-ness for sufficiently[!] zero-padded
 * inputs is |n < OSSL_FN_BITS| or |n / OSSL_FN_BITS| being non-secret.
 */
int OSSL_FN_rshift(OSSL_FN *r, const OSSL_FN *a, int n)
{
    size_t i, nw;
    unsigned int lb, rb;
    const OSSL_FN_ULONG *ap = a->d;
    OSSL_FN_ULONG *rp = r->d;
    size_t rl = (size_t)r->dsize;
    size_t al = (size_t)a->dsize;

    if (n < 0) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_SHIFT);
        return 0;
    }

    nw = (size_t)n / OSSL_FN_BITS;
    rb = (unsigned int)n % OSSL_FN_BITS;
    lb = OSSL_FN_BITS - rb;

    /*
     * Work from the low end to support r == a.  Each result limb only
     * depends on the corresponding source limb and the limb just above it,
     * neither of which has been overwritten yet when walking upward.
     */
    for (i = 0; i < rl; i++) {
        size_t src_idx = i + nw;
        OSSL_FN_ULONG limb = 0;

        if (src_idx < al) {
            limb = ap[src_idx] >> rb;
            if (rb != 0 && src_idx + 1 < al)
                limb |= (ap[src_idx + 1] << lb) & OSSL_FN_MASK;
        }
        rp[i] = limb;
    }

    return 1;
}

int OSSL_FN_rshift1(OSSL_FN *r, const OSSL_FN *a)
{
    OSSL_FN_ULONG *rp = r->d;
    const OSSL_FN_ULONG *ap = a->d;
    size_t rl = (size_t)r->dsize;
    size_t al = (size_t)a->dsize;
    size_t i;

    /*
     * Work from the low end to support r == a.  Each result limb only
     * depends on the corresponding source limb and the limb just above it,
     * neither of which has been overwritten yet when walking upward.
     */
    for (i = 0; i < rl; i++) {
        OSSL_FN_ULONG limb = 0;

        if (i < al) {
            limb = ap[i] >> 1;
            if (i + 1 < al)
                limb |= (ap[i + 1] << (OSSL_FN_BITS - 1)) & OSSL_FN_MASK;
        }
        rp[i] = limb;
    }

    return 1;
}
