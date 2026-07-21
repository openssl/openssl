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
#include "crypto/bn.h"
#include "internal/safe_math.h"
#include "fn_local.h"

OSSL_SAFE_MATH_ADDU(size_t, size_t, OSSL_SAFE_MATH_MAXU(size_t))

OSSL_FN_MONT_CTX *OSSL_FN_MONT_CTX_new(const OSSL_FN *mod)
{
    size_t i, j;

    if (mod == NULL || mod->dsize <= 0 || (mod->d[0] & OSSL_FN_ULONG_C(1)) == 0)
        return NULL;

    size_t mod_size = sizeof(OSSL_FN) + mod->dsize * sizeof(OSSL_FN_ULONG);
    size_t ctx_size = sizeof(OSSL_FN_MONT_CTX) + 2 * mod_size;
    OSSL_FN_MONT_CTX *ctx = OPENSSL_zalloc(ctx_size);
    if (ctx == NULL)
        return NULL;

    ctx->ri = mod->dsize * OSSL_FN_BYTES * 8;
    OSSL_FN *N = (OSSL_FN *)ctx->memory;
    OSSL_FN *RR = (OSSL_FN *)(ctx->memory + mod_size / sizeof(OSSL_FN_ULONG));
    N->dsize = RR->dsize = mod->dsize;

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

    memcpy(N->d, mod->d, mod->dsize * sizeof(OSSL_FN_ULONG));

    size_t mod_len = OSSL_FN_num_bits(mod);
    if (ossl_unlikely(mod_len <= 1))
        return ctx;

    RR->d[0] = 1;
    size_t rr_bits = 2 * (size_t)ctx->ri;
    for (i = 0; i < rr_bits;) {
        j = mod_len - OSSL_FN_num_bits(RR);
        if (j > rr_bits - i)
            j = rr_bits - i;
        if (j > 0) {
            OSSL_FN_lshift(RR, RR, (int)j);
            i += j;
        }
        if (OSSL_FN_cmp(RR, mod) < 0) {
            if (i == rr_bits)
                break;
            OSSL_FN_lshift1(RR, RR);
            i++;
        }
        OSSL_FN_sub(RR, RR, mod);
    }

    ctx->N = N;
    ctx->RR = RR;

    return ctx;
}

void OSSL_FN_MONT_CTX_free(OSSL_FN_MONT_CTX *ctx)
{
    if (ctx != NULL)
        OPENSSL_free(ctx);
}

OSSL_FN_MONT_CTX *OSSL_FN_MONT_CTX_dup(OSSL_FN_MONT_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;
    size_t mod_size = sizeof(OSSL_FN) + ctx->N->dsize * sizeof(OSSL_FN_ULONG);
    size_t ctx_size = sizeof(OSSL_FN_MONT_CTX) + 2 * mod_size;
    OSSL_FN_MONT_CTX *ret = OPENSSL_zalloc(ctx_size);
    if (ret == NULL)
        return NULL;
    ret->N = (OSSL_FN *)ret->memory;
    ret->RR = (OSSL_FN *)(ret->memory + mod_size / sizeof(OSSL_FN_ULONG));

    ret->ri = ctx->ri;
    memcpy(ret->n0, ctx->n0, 2 * sizeof(OSSL_FN_ULONG));
    memcpy(ret->memory, ctx->memory, 2 * mod_size);
    return ret;
}

size_t OSSL_FN_mul_mont_quick_ctx_size(OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(mont != NULL))
        return 0;
    return OSSL_FN_CTX_size(1, 1, (size_t)mont->N->dsize + 2);
}

/*
 * Montgomery multiplication r = (a*b)/(2^mont->ri) mod mont->N.
 * r, a, b, and mont->N must be of the same size,
 * a and b must be less than mont->N.
 */
int OSSL_FN_mul_mont_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(r != NULL) || !ossl_assert(a != NULL)
        || !ossl_assert(b != NULL) || !ossl_assert(mont != NULL))
        return 0;

    OSSL_FN_ULONG m, carry = 0;
    int i, j, ret = 0;
    int len = mont->N->dsize;

#if defined(OPENSSL_BN_ASM_MONT)
    if (len > 1)
        if (bn_mul_mont(r->d, a->d, b->d, mont->N->d, mont->n0, len) != 0)
            return 1;
#endif

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    OSSL_FN *T = OSSL_FN_CTX_get_limbs(ctx, len + 2);
    if (T == NULL)
        goto end;
    OSSL_FN_clear(T);

    for (i = 0; i < len; i++) {
        carry = bn_mul_add_words(T->d, a->d, len, b->d[i]);
        T->d[len] += carry;
        if (T->d[len] < carry)
            T->d[len + 1]++;
        m = T->d[0] * mont->n0[0];
        carry = bn_mul_add_words(T->d, mont->N->d, len, m);
        T->d[len] += carry;
        if (T->d[len] < carry)
            T->d[len + 1]++;
        for (j = 0; j <= len; j++)
            T->d[j] = T->d[j + 1];
        T->d[len + 1] = 0;
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

size_t OSSL_FN_mul_mont_ctx_size(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(a != NULL) || !ossl_assert(b != NULL)
        || !ossl_assert(mont != NULL))
        return 0;

    int len = mont->N->dsize;
    int num = 0;
    size_t ret = 0, tmp;
    int err = 0;

    if (a->dsize != len || OSSL_FN_cmp(a, mont->N) >= 0) {
        num++;
        tmp = OSSL_FN_mod_ctx_size(NULL, a, mont->N);
        if (tmp > ret)
            ret = tmp;
    }

    if (b->dsize != len || OSSL_FN_cmp(b, mont->N) >= 0) {
        num++;
        tmp = OSSL_FN_mod_ctx_size(NULL, b, mont->N);
        if (tmp > ret)
            ret = tmp;
    }

    if (r != NULL && r->dsize != len)
        num++;

    tmp = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    if (tmp > ret)
        ret = tmp;

    ret = safe_add_size_t(ret, OSSL_FN_CTX_size(1, num, num * (size_t)len),
        &err);

    return err == 0 ? ret : 0;
}

int OSSL_FN_mul_mont(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(r != NULL) || !ossl_assert(a != NULL)
        || !ossl_assert(b != NULL) || !ossl_assert(mont != NULL)
        || !ossl_assert(ctx != NULL))
        return 0;

    int len = mont->N->dsize;
    const OSSL_FN *aa = a;
    const OSSL_FN *bb = b;
    OSSL_FN *rr = r;
    OSSL_FN *tmp;
    int ret = 0;

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    if (a->dsize != len || OSSL_FN_cmp(a, mont->N) >= 0) {
        tmp = OSSL_FN_CTX_get_limbs(ctx, len);
        if (tmp == NULL)
            goto end;
        if (OSSL_FN_mod(tmp, a, mont->N, ctx) == 0)
            goto end;
        aa = tmp;
    }

    if (b->dsize != len || OSSL_FN_cmp(b, mont->N) >= 0) {
        tmp = OSSL_FN_CTX_get_limbs(ctx, len);
        if (tmp == NULL)
            goto end;
        if (OSSL_FN_mod(tmp, b, mont->N, ctx) == 0)
            goto end;
        bb = tmp;
    }

    if (r->dsize != len) {
        rr = OSSL_FN_CTX_get_limbs(ctx, len);
        if (rr == NULL)
            goto end;
    }

    ret = OSSL_FN_mul_mont_quick(rr, aa, bb, mont, ctx);

    if (r != rr)
        ret &= (OSSL_FN_copy_truncate(r, rr) != NULL);

end:
    OSSL_FN_CTX_end(ctx, token);
    return ret;
}

size_t OSSL_FN_to_mont_ctx_size(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(a != NULL) || !ossl_assert(mont != NULL))
        return 0;

    int len = mont->N->dsize;
    int num = 0;
    size_t ret = 0, tmp;
    int err = 0;

    if (a->dsize != len || OSSL_FN_cmp(a, mont->N) >= 0) {
        num++;
        tmp = OSSL_FN_mod_ctx_size(NULL, a, mont->N);
        if (tmp > ret)
            ret = tmp;
    }

    if (r != NULL && r->dsize != len)
        num++;

    tmp = OSSL_FN_mul_mont_quick_ctx_size(NULL, NULL, NULL, mont);
    if (tmp > ret)
        ret = tmp;

    ret = safe_add_size_t(ret, OSSL_FN_CTX_size(1, num, num * (size_t)len),
        &err);

    return err == 0 ? ret : 0;
}

int OSSL_FN_to_mont(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    if (!ossl_assert(mont != NULL)
        || !ossl_assert(r != NULL) || !ossl_assert(r->dsize == mont->N->dsize))
        return 0;
    return OSSL_FN_mul_mont(r, a, mont->RR, mont, ctx);
}

size_t OSSL_FN_from_mont_ctx_size(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont)
{
    if (!ossl_assert(mont != NULL))
        return 0;

    return OSSL_FN_CTX_size(1, 1, (size_t)mont->N->dsize + 2);
}

int OSSL_FN_from_mont(OSSL_FN *r, const OSSL_FN *a,
    OSSL_FN_MONT_CTX *mont, OSSL_FN_CTX *ctx)
{
    int i, j, ret = 0;
    OSSL_FN_ULONG m, carry;

    if (!ossl_assert(r != NULL) || !ossl_assert(a != NULL)
        || !ossl_assert(mont != NULL) || !ossl_assert(ctx != NULL))
        return 0;
    int len = mont->N->dsize;
    if (!ossl_assert(r->dsize == len) || !ossl_assert(a->dsize == len))
        return 0;

    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    OSSL_FN *T = OSSL_FN_CTX_get_limbs(ctx, len + 2);
    if (T == NULL)
        goto end;

    OSSL_FN_copy(T, a);
    for (i = 0; i < len; i++) {
        m = T->d[0] * mont->n0[0];
        carry = bn_mul_add_words(T->d, mont->N->d, len, m);
        T->d[len] += carry;
        if (T->d[len] < carry)
            T->d[len + 1]++;
        for (j = 0; j <= len; j++)
            T->d[j] = T->d[j + 1];
        T->d[len + 1] = 0;
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
