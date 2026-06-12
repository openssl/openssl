/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Details about Montgomery multiplication algorithms can be found at
 * http://security.ece.orst.edu/publications.html, e.g.
 * http://security.ece.orst.edu/koc/papers/j37acmon.pdf and
 * sections 3.8 and 4.2 in http://security.ece.orst.edu/koc/papers/r01rsasw.pdf
 */

#include "crypto/fn.h"
#include "fn_local.h"
#include "../bn/bn_local.h"

OSSL_FN_MONT_CTX *OSSL_FN_MONT_CTX_new(const OSSL_FN *mod)
{
    int i, j;

    if (mod == NULL || mod->dsize <= 0 || (mod->d[0] & OSSL_FN_ULONG_C(1)) == 0)
        return NULL;

    size_t mod_size = sizeof(OSSL_FN) + mod->dsize * sizeof(OSSL_FN_ULONG);
    size_t ctx_size = sizeof(OSSL_FN_MONT_CTX) + 2 * mod_size;
    OSSL_FN_MONT_CTX *ctx = OPENSSL_zalloc(ctx_size);
    if (ctx == NULL)
        return NULL;

    ctx->ri = mod->dsize * OSSL_FN_BYTES * 8;
    ctx->N = (OSSL_FN *)ctx->memory;
    ctx->RR = (OSSL_FN *)(ctx->memory + mod_size / sizeof(OSSL_FN_ULONG));
    ctx->N->dsize = ctx->RR->dsize = mod->dsize;

    uint64_t tmod; /* The lower 64 bits of the module */
    if (ossl_unlikely(mod->dsize == 1))
        tmod = mod->d[0];
    else
#if OSSL_FN_BYTES == 4
        tmod = (uint64_t)mod->d[1] << 32 | (uint64_t)mod->d[0];
#elif OSSL_FN_BYTES == 8
        tmod = mod->d[0];
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

    /* Solve the equation tmod * n0 = -1 (mod 2^64) using Hensel's lifting */
    uint64_t inv = 1;
    for (i = 0; i < 6; i++)
        inv *= 2 - tmod * inv;
#if OSSL_FN_BYTES == 4
    inv = 0 - inv;
    ctx->n0[0] = (OSSL_FN_ULONG)(inv & 0xFFFFFFFF);
    ctx->n0[1] = (OSSL_FN_ULONG)(inv >> 32);
#elif OSSL_FN_BYTES == 8
    ctx->n0[0] = 0 - inv;
    ctx->n0[1] = 0;
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

    memcpy(ctx->N->d, mod->d, mod->dsize * sizeof(OSSL_FN_ULONG));

    int mod_len = OSSL_FN_num_bits(mod);
    if (ossl_unlikely(mod_len <= 1))
        return ctx;

    ctx->RR->d[0] = 1;
    for (i = 0; i < 2 * ctx->ri;) {
        j = mod_len - OSSL_FN_num_bits(ctx->RR);
        if (j > 2 * ctx->ri - i)
            j = 2 * ctx->ri - i;
        if (j > 0) {
            OSSL_FN_lshift(ctx->RR, j);
            i += j;
        }
        if (OSSL_FN_cmp(ctx->RR, mod) < 0) {
            if (i == 2 * ctx->ri)
                break;
            OSSL_FN_lshift(ctx->RR, 1);
            i++;
        }
        OSSL_FN_sub(ctx->RR, ctx->RR, mod);
    }

    return ctx;
}

void OSSL_FN_MONT_CTX_free(OSSL_FN_MONT_CTX *ctx)
{
    if (ctx != NULL)
        OPENSSL_free(ctx);
}

/*
 * Montgomery multiplication r = (a*b)/(2^mont->ri) mod mont->N.
 * r, a, b, and mont->N must be of the same size,
 * a and b must be less than mont->N.
 */
int ossl_fn_mul_mont(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    OSSL_FN_ULONG m, carry = 0;
    int i, j, ret = 0;
    int num = mont->N->dsize;

#if defined(OPENSSL_BN_ASM_MONT)
    if (num > 1 && b->dsize == num) {
        if (bn_mul_mont(r->d, a->d, b->d, mont->N->d, mont->n0, num)) {
            return 1;
        }
    }
#endif

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    OSSL_FN *T = OSSL_FN_CTX_get_limbs(ctx, num + 2);
    if (T == NULL)
        goto end;
    OSSL_FN_clear(T);

    for (i = 0; i < num; i++) {
        carry = bn_mul_add_words(T->d, a->d, num, b->d[i]);
        T->d[num] += carry;
        if (T->d[num] < carry)
            T->d[num + 1]++;
        m = T->d[0] * mont->n0[0];
        carry = bn_mul_add_words(T->d, mont->N->d, num, m);
        T->d[num] += carry;
        if (T->d[num] < carry)
            T->d[num + 1]++;
        for (j = 0; j <= num; j++)
            T->d[j] = T->d[j + 1];
        T->d[num + 1] = 0;
    }

    if (OSSL_FN_cmp(T, mont->N) >= 0) {
        OSSL_FN_sub(r, T, mont->N);
    } else {
        OSSL_FN_copy_truncate(r, T);
    }

    ret = 1;
end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

int OSSL_FN_mul_mont(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (r == NULL || a == NULL || b == NULL || mont == NULL || ctx == NULL)
        return 0;
    int num = mont->N->dsize;
    if (a->dsize != num || b->dsize != num || r->dsize != num
        || OSSL_FN_cmp(a, mont->N) >= 0 || OSSL_FN_cmp(b, mont->N) >= 0)
        return 0;

    return ossl_fn_mul_mont(r, a, b, mont, ctx);
}

int OSSL_FN_to_mont(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (mont == NULL)
        return 0;
    return OSSL_FN_mul_mont(r, a, mont->RR, mont, ctx);
}

int OSSL_FN_from_mont(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    int i, j, ret = 0;
    OSSL_FN_ULONG m, carry;

    if (r == NULL || a == NULL || mont == NULL || ctx == NULL)
        return 0;
    int num = mont->N->dsize;
    if (r->dsize != num || a->dsize != num || OSSL_FN_cmp(a, mont->N) >= 0)
        return 0;

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    OSSL_FN *T = OSSL_FN_CTX_get_limbs(ctx, num + 2);
    if (T == NULL)
        goto end;

    OSSL_FN_copy(T, a);
    for (i = 0; i < num; i++) {
        m = T->d[0] * mont->n0[0];
        carry = bn_mul_add_words(T->d, mont->N->d, num, m);
        T->d[num] += carry;
        if (T->d[num] < carry)
            T->d[num + 1]++;
        for (j = 0; j <= num; j++)
            T->d[j] = T->d[j + 1];
        T->d[num + 1] = 0;
    }

    if (OSSL_FN_cmp(T, mont->N) >= 0) {
        OSSL_FN_sub(r, T, mont->N);
    } else {
        OSSL_FN_copy_truncate(r, T);
    }

    ret = 1;
end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}
