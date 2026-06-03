/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Details about Montgomery multiplication algorithms can be found in
 * https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf
 * and https://cetinkayakoc.net/docs/r01.pdf
 */

#include "internal/cryptlib.h"
#include "crypto/fn.h"
#include "bn_local.h"

#define MONT_WORD /* use the faster word-based algorithm */

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx)
{
    if (r == NULL || a == NULL || b == NULL || mont == NULL || ctx == NULL)
        return 0;

    int ret = bn_mul_mont_fixed_top(r, a, b, mont, ctx);

    bn_correct_top(r);
    bn_check_top(r);

    return ret;
}

/* // All parameters must be non‑NULL. The caller is responsible for this */
int bn_mul_mont_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx)
{
    int ret = 0;
    if (ossl_unlikely(mont->N.data == NULL))
        return 0;
    int modsize = mont->N.data->dsize;
    BIGNUM *a_tmp = NULL, *b_tmp = NULL, *r_tmp = NULL;

    if (a->data != NULL && a->data->dsize == modsize
#if !defined(OPENSSL_BN_ASM_MONT)
        && OSSL_FN_cmp(a->data, mont->N.data) < 0
#endif
    ) {
        a_tmp = (BIGNUM *)a;
    } else {
        a_tmp = bn_new_internal(modsize, BN_get_flags(a, BN_FLG_SECURE));
        if (ossl_unlikely(a_tmp == NULL))
            goto end;
        /* TODO(FIXNUM): Check if it is necessary with OSSL_FN_nnmod() */
        if (a->flags & BN_FLG_FIXED_TOP) {
            a_tmp->flags |= BN_FLG_FIXED_TOP;
            a_tmp->top = modsize;
        }
        /* TODO(FIXNUM): change to OSSL_FN_nnmod() */
        if (BN_nnmod(a_tmp, a, &mont->N, ctx) == 0)
            goto end;
        /* TODO(FIXNUM): Check if it is necessary with OSSL_FN_nnmod() */
        memset(a_tmp->data->d + a_tmp->top, 0,
            (modsize - a_tmp->top) * sizeof(OSSL_FN_ULONG));
    }

    if (b->data != NULL && b->data->dsize == modsize
#if !defined(OPENSSL_BN_ASM_MONT)
        && OSSL_FN_cmp(b->data, mont->N.data) < 0
#endif
    ) {
        b_tmp = (BIGNUM *)b;
    } else {
        b_tmp = bn_new_internal(modsize, BN_get_flags(b, BN_FLG_SECURE));
        if (ossl_unlikely(b_tmp == NULL))
            goto end;
        /* TODO(FIXNUM): Check if it is necessary with OSSL_FN_nnmod() */
        if (b->flags & BN_FLG_FIXED_TOP) {
            b_tmp->flags |= BN_FLG_FIXED_TOP;
            b_tmp->top = modsize;
        }
        /* TODO(FIXNUM): change to OSSL_FN_nnmod() */
        if (BN_nnmod(b_tmp, b, &mont->N, ctx) == 0)
            goto end;
        /* TODO(FIXNUM): Check if it is necessary with OSSL_FN_nnmod() */
        memset(b_tmp->data->d + b_tmp->top, 0,
            (modsize - b_tmp->top) * sizeof(OSSL_FN_ULONG));
    }

    if (r->data != NULL && r->data->dsize == modsize) {
        r_tmp = r;
    } else {
        r_tmp = bn_new_internal(modsize,
            BN_get_flags(a, BN_FLG_SECURE) && BN_get_flags(b, BN_FLG_SECURE));
        if (ossl_unlikely(r_tmp == NULL))
            goto end;
    }
    r_tmp->flags |= BN_FLG_FIXED_TOP;
    r_tmp->top = modsize;

    OSSL_FN_CTX *fnctx = bn_ctx_acquire_ossl_fn_ctx(ctx, 1, 1, modsize + 2);
    if (ossl_unlikely(fnctx == NULL))
        goto end;

    OSSL_FN *rf = bn_acquire_ossl_fn(r_tmp, modsize);
    if (ossl_unlikely(rf == NULL)) {
        bn_ctx_release_ossl_fn_ctx(ctx);
        goto end;
    }

    ret = ossl_fn_mul_mont(rf, a_tmp->data, b_tmp->data, mont->fn_mont_ctx, fnctx);
    bn_release(r_tmp, modsize);
    bn_ctx_release_ossl_fn_ctx(ctx);
    if (ret) {
        r_tmp->neg = a->neg ^ b->neg;
        bn_set_top(r_tmp, mont->N.top);
        r_tmp->flags |= BN_FLG_FIXED_TOP;
        if (r_tmp != r) {
            if (BN_get_flags(r, BN_FLG_STATIC_DATA))
                ret = ossl_likely(BN_copy(r, r_tmp) != NULL);
            else
                ret = ossl_likely(bn_copy_resized(r, r_tmp) != NULL);
        }
    }

end:
    if (a_tmp != a)
        BN_free(a_tmp);
    if (b_tmp != b)
        BN_free(b_tmp);
    if (r_tmp != r)
        BN_free(r_tmp);
    return ret;
}

int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx)
{
    int retn;

    if (ret == NULL || a == NULL || mont == NULL || ctx == NULL)
        return 0;

    retn = bn_from_mont_fixed_top(ret, a, mont, ctx);
    bn_correct_top(ret);
    bn_check_top(ret);

    return retn;
}

int bn_from_mont_fixed_top(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx)
{
    int retn = 0;
    int modsize = mont->N.data->dsize;
    BIGNUM *a_tmp = NULL, *r_tmp = NULL;

    if (a->data != NULL && a->data->dsize == modsize
#if !defined(OPENSSL_BN_ASM_MONT)
        && OSSL_FN_cmp(a->data, mont->N.data) < 0
#endif
    ) {
        a_tmp = (BIGNUM *)a;
    } else {
        a_tmp = bn_new_internal(modsize, BN_get_flags(a, BN_FLG_SECURE));
        if (ossl_unlikely(a_tmp == NULL))
            goto end;
        /* TODO(FIXNUM): Check if it is necessary with OSSL_FN_nnmod() */
        if (a->flags & BN_FLG_FIXED_TOP) {
            a_tmp->flags |= BN_FLG_FIXED_TOP;
            a_tmp->top = modsize;
        }
        /* TODO(FIXNUM): change to OSSL_FN_nnmod() */
        if (BN_nnmod(a_tmp, a, &mont->N, ctx) == 0)
            goto end;
        /* TODO(FIXNUM): Check if it is necessary with OSSL_FN_nnmod() */
        memset(a_tmp->data->d + a_tmp->top, 0,
            (modsize - a_tmp->top) * sizeof(OSSL_FN_ULONG));
    }

    if (ret->data != NULL && ret->data->dsize == modsize) {
        r_tmp = ret;
    } else {
        r_tmp = bn_new_internal(modsize, BN_get_flags(a, BN_FLG_SECURE));
        if (ossl_unlikely(r_tmp == NULL))
            goto end;
    }
    r_tmp->flags |= BN_FLG_FIXED_TOP;
    r_tmp->top = modsize;

    OSSL_FN_CTX *fnctx = bn_ctx_acquire_ossl_fn_ctx(ctx, 1, 1, modsize + 2);
    if (ossl_unlikely(fnctx == NULL))
        goto end;

    OSSL_FN *rf = bn_acquire_ossl_fn(r_tmp, modsize);
    if (ossl_unlikely(rf == NULL)) {
        bn_ctx_release_ossl_fn_ctx(ctx);
        goto end;
    }

    retn = OSSL_FN_from_mont(rf, a_tmp->data, mont->fn_mont_ctx, fnctx);
    bn_release(r_tmp, modsize);
    bn_ctx_release_ossl_fn_ctx(ctx);
    if (retn) {
        r_tmp->neg = a->neg;
        if (r_tmp != ret)
            if (ossl_unlikely(bn_copy_resized(ret, r_tmp) == NULL))
                retn = 0;
    }

end:
    if (a_tmp != a)
        BN_free(a_tmp);
    if (r_tmp != ret)
        BN_free(r_tmp);
    return retn;
}

int bn_to_mont_fixed_top(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx)
{
    return bn_mul_mont_fixed_top(r, a, &(mont->RR), mont, ctx);
}

BN_MONT_CTX *BN_MONT_CTX_new(void)
{
    BN_MONT_CTX *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;

    BN_MONT_CTX_init(ret);
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
    ctx->ri = 0;
    bn_init(&ctx->RR);
    bn_init(&ctx->N);
    ctx->n0 = NULL;
    ctx->flags = 0;
}

static void bn_mont_ctx_reinit(BN_MONT_CTX *ctx)
{
    OSSL_FN_MONT_CTX_free(ctx->fn_mont_ctx);
    ctx->fn_mont_ctx = NULL;
    bn_init(&ctx->RR);
    bn_init(&ctx->N);
    ctx->n0 = NULL;
    ctx->ri = 0;
}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
{
    if (mont == NULL)
        return;
    bn_mont_ctx_reinit(mont);
    if (mont->flags & BN_FLG_MALLOCED)
        OPENSSL_free(mont);
}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
    if (mont == NULL || mod == NULL || BN_is_zero(mod))
        return 0;
    const OSSL_FN *fnmod;
    BIGNUM *mod_dup = NULL;
    int mod_size = mod->top;

    if (mod->data != NULL && mod->data->dsize == mod_size) {
        fnmod = mod->data;
    } else {
        mod_dup = bn_new_internal(mod_size, BN_get_flags(mod, BN_FLG_SECURE));
        if (ossl_unlikely(mod_dup == NULL))
            return 0;
        if (!ossl_fn_copy_internal_limbs(mod_dup->data, mod->d, mod_size)) {
            BN_free(mod_dup);
            return 0;
        }
        bn_correct_top(mod_dup);
        fnmod = mod_dup->data;
    }
    bn_mont_ctx_reinit(mont);
    mont->fn_mont_ctx = OSSL_FN_MONT_CTX_new(fnmod);
    BN_free(mod_dup);
    if (ossl_unlikely(mont->fn_mont_ctx == NULL)) {
        bn_mont_ctx_reinit(mont);
        return 0;
    }
    bn_from_ossl_fn(&mont->RR, mont->fn_mont_ctx->RR);
    bn_from_ossl_fn(&mont->N, mont->fn_mont_ctx->N);
    mont->n0 = mont->fn_mont_ctx->n0;
    mont->ri = mont->fn_mont_ctx->ri;
    return 1;
}

BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
{
    if (to == from)
        return to;

    bn_mont_ctx_reinit(to);
    to->fn_mont_ctx = OSSL_FN_MONT_CTX_dup(from->fn_mont_ctx);
    if (ossl_unlikely(to->fn_mont_ctx == NULL)) {
        bn_mont_ctx_reinit(to);
        return NULL;
    }
    bn_from_ossl_fn(&to->RR, to->fn_mont_ctx->RR);
    bn_from_ossl_fn(&to->N, to->fn_mont_ctx->N);
    to->n0 = to->fn_mont_ctx->n0;
    to->ri = to->fn_mont_ctx->ri;
    return to;
}

BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
    const BIGNUM *mod, BN_CTX *ctx)
{
    BN_MONT_CTX *ret;

    if (!CRYPTO_THREAD_read_lock(lock))
        return NULL;
    ret = *pmont;
    CRYPTO_THREAD_unlock(lock);
    if (ret)
        return ret;

    /*
     * We don't want to serialize globally while doing our lazy-init math in
     * BN_MONT_CTX_set. That punishes threads that are doing independent
     * things. Instead, punish the case where more than one thread tries to
     * lazy-init the same 'pmont', by having each do the lazy-init math work
     * independently and only use the one from the thread that wins the race
     * (the losers throw away the work they've done).
     */
    ret = BN_MONT_CTX_new();
    if (ret == NULL)
        return NULL;
    if (!BN_MONT_CTX_set(ret, mod, ctx)) {
        BN_MONT_CTX_free(ret);
        return NULL;
    }

    /* The locked compare-and-set, after the local work is done. */
    if (!CRYPTO_THREAD_write_lock(lock)) {
        BN_MONT_CTX_free(ret);
        return NULL;
    }

    if (*pmont) {
        BN_MONT_CTX_free(ret);
        ret = *pmont;
    } else
        *pmont = ret;
    CRYPTO_THREAD_unlock(lock);
    return ret;
}

int ossl_bn_mont_ctx_set(BN_MONT_CTX *ctx, const BIGNUM *modulus, int ri, const unsigned char *rr,
    int rrlen, uint32_t nlo, uint32_t nhi)
{
    int mod_size = modulus->top;
    size_t fn_size = sizeof(OSSL_FN) + mod_size * sizeof(OSSL_FN_ULONG);
    size_t fnctx_size = sizeof(OSSL_FN_MONT_CTX) + 2 * fn_size;
    bn_mont_ctx_reinit(ctx);
    ctx->fn_mont_ctx = OPENSSL_zalloc(fnctx_size);
    if (ossl_unlikely(ctx->fn_mont_ctx == NULL)) {
        bn_mont_ctx_reinit(ctx);
        return 0;
    }

    ctx->fn_mont_ctx->ri = ri;
    ctx->fn_mont_ctx->N = (OSSL_FN *)ctx->fn_mont_ctx->memory;
    ctx->fn_mont_ctx->RR = (OSSL_FN *)(ctx->fn_mont_ctx->memory
        + fn_size / sizeof(OSSL_FN_ULONG));
    ctx->fn_mont_ctx->N->dsize = ctx->fn_mont_ctx->RR->dsize = mod_size;

    if (modulus->data != NULL)
        ossl_fn_copy_internal_limbs(ctx->fn_mont_ctx->N, modulus->data->d, mod_size);
    else if (modulus->d != NULL)
        ossl_fn_copy_internal_limbs(ctx->fn_mont_ctx->N, modulus->d, mod_size);

    BIGNUM *rrbn = BN_bin2bn(rr, rrlen, NULL);
    if (rrbn == NULL) {
        bn_mont_ctx_reinit(ctx);
        return 0;
    }
    ossl_fn_copy_internal_limbs(ctx->fn_mont_ctx->RR, rrbn->d, mod_size);
    BN_free(rrbn);

#if (BN_BITS2 <= 32) && defined(OPENSSL_BN_ASM_MONT)
    ctx->fn_mont_ctx->n0[0] = nlo;
    ctx->fn_mont_ctx->n0[1] = nhi;
#elif BN_BITS2 <= 32
    ctx->fn_mont_ctx->n0[0] = nlo;
    ctx->fn_mont_ctx->n0[1] = 0;
#else
    ctx->fn_mont_ctx->n0[0] = ((BN_ULONG)nhi << 32) | nlo;
    ctx->fn_mont_ctx->n0[1] = 0;
#endif

    bn_from_ossl_fn(&ctx->RR, ctx->fn_mont_ctx->RR);
    bn_from_ossl_fn(&ctx->N, ctx->fn_mont_ctx->N);
    ctx->n0 = ctx->fn_mont_ctx->n0;
    ctx->ri = ctx->fn_mont_ctx->ri;
    return 1;
}

int ossl_bn_mont_ctx_eq(const BN_MONT_CTX *m1, const BN_MONT_CTX *m2)
{
    if (m1->ri != m2->ri)
        return 0;
    if (BN_cmp(&m1->RR, &m2->RR) != 0)
        return 0;
    if (m1->flags != m2->flags)
        return 0;
    if (m1->n0[0] != m2->n0[0])
        return 0;
    if (m1->n0[1] != m2->n0[1])
        return 0;
    return 1;
}
