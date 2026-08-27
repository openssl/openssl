/*
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include "dsa_local.h"
#include <openssl/asn1.h>
#include "internal/deterministic_nonce.h"

#define MIN_DSA_SIGN_QBITS 128
#define MAX_DSA_SIGN_RETRIES 8

static DSA_SIG *dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
static int dsa_sign_setup_no_digest(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
    BIGNUM **rp);
static int dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
    BIGNUM **rp, const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq);
static int dsa_do_verify(const unsigned char *dgst, int dgst_len,
    DSA_SIG *sig, DSA *dsa);
static int dsa_init(DSA *dsa);
static int dsa_finish(DSA *dsa);
static BIGNUM *dsa_mod_inverse_fermat(const OSSL_FN *k, const BIGNUM *q,
    BN_CTX *ctx);

static const DSA_METHOD openssl_dsa_meth = {
    "OpenSSL DSA method",
    dsa_do_sign,
    dsa_sign_setup_no_digest,
    dsa_do_verify,
    NULL, /* dsa_mod_exp, */
    NULL, /* dsa_bn_mod_exp, */
    dsa_init,
    dsa_finish,
    DSA_FLAG_FIPS_METHOD,
    NULL,
    NULL,
    NULL
};

static const DSA_METHOD *default_DSA_method = &openssl_dsa_meth;

#ifndef FIPS_MODULE
void DSA_set_default_method(const DSA_METHOD *meth)
{
    default_DSA_method = meth;
}
#endif /* FIPS_MODULE */

const DSA_METHOD *DSA_get_default_method(void)
{
    return default_DSA_method;
}

const DSA_METHOD *DSA_OpenSSL(void)
{
    return &openssl_dsa_meth;
}

DSA_SIG *ossl_dsa_do_sign_int(const unsigned char *dgst, int dlen, DSA *dsa,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    BIGNUM *kinv = NULL;
    BIGNUM *m, *blind, *blindm, *tmp;
    BN_CTX *ctx = NULL;
    int reason = ERR_R_BN_LIB;
    DSA_SIG *ret = NULL;
    int rv = 0;
    int retries = 0;

    if (dsa->params.p == NULL
        || dsa->params.q == NULL
        || dsa->params.g == NULL) {
        reason = DSA_R_MISSING_PARAMETERS;
        goto err;
    }
    if (dsa->priv_key == NULL) {
        reason = DSA_R_MISSING_PRIVATE_KEY;
        goto err;
    }

    ret = DSA_SIG_new();
    if (ret == NULL)
        goto err;
    ret->r = BN_new();
    ret->s = BN_new();
    if (ret->r == NULL || ret->s == NULL)
        goto err;

    ctx = BN_CTX_new_ex(dsa->libctx);
    if (ctx == NULL)
        goto err;
    m = BN_CTX_get(ctx);
    blind = BN_CTX_get(ctx);
    blindm = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

redo:
    if (!dsa_sign_setup(dsa, ctx, &kinv, &ret->r, dgst, dlen,
            nonce_type, digestname, libctx, propq))
        goto err;

    if (dlen > BN_num_bytes(dsa->params.q))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dlen = BN_num_bytes(dsa->params.q);
    if (BN_bin2bn(dgst, dlen, m) == NULL)
        goto err;

    /*
     * The normal signature calculation is:
     *
     *   s := k^-1 * (m + r * priv_key) mod q
     *
     * We will blind this to protect against side channel attacks
     *
     *   s := blind^-1 * k^-1 * (blind * m + blind * r * priv_key) mod q
     */

    {
        const OSSL_FN *fn_kinv = NULL, *fn_q = NULL, *fn_priv = NULL;
        OSSL_FN *fn_r = NULL, *fn_s = NULL, *fn_m = NULL;
        OSSL_FN *fn_blind = NULL, *fn_blindm = NULL, *fn_tmp = NULL;
        OSSL_FN_CTX *fn_ctx = NULL;
        const void *token = NULL;
        size_t fn_size, mod_mul_size, mod_exp_size;
        int qbits, qlimbs, fn_bits;
        int fn_ok = 0;
        /* bn_release() widths; full width until success is known */
        int r_sz, s_sz, m_sz, blind_sz, blindm_sz, tmp_sz;

        qbits = BN_num_bits(dsa->params.q);
        qlimbs = (qbits + BN_BITS2 - 1) / BN_BITS2;
        r_sz = s_sz = m_sz = blind_sz = blindm_sz = tmp_sz = qlimbs;

        fn_q = bn_get_ossl_fn(dsa->params.q);
        fn_priv = bn_get_ossl_fn(dsa->priv_key);
        fn_kinv = bn_get_ossl_fn(kinv);
        if (fn_q == NULL || fn_priv == NULL || fn_kinv == NULL)
            goto err;

        /*
         * Acquire the writable values at the q width before the
         * OSSL_FN_CTX sizing, which derives from their allocated widths.
         */
        if ((fn_r = bn_acquire_ossl_fn(ret->r, qlimbs)) == NULL
            || (fn_s = bn_acquire_ossl_fn(ret->s, qlimbs)) == NULL
            || (fn_m = bn_acquire_ossl_fn(m, qlimbs)) == NULL
            || (fn_blind = bn_acquire_ossl_fn(blind, qlimbs)) == NULL
            || (fn_blindm = bn_acquire_ossl_fn(blindm, qlimbs)) == NULL
            || (fn_tmp = bn_acquire_ossl_fn(tmp, qlimbs)) == NULL)
            goto release;

        /*
         * Each operation pops its arena frame when done, so sequential
         * operations reuse the space: the body frame needs room for the
         * largest single operation.  All operands are q-wide.
         */
        mod_mul_size = OSSL_FN_mod_mul_ctx_size(fn_tmp, fn_tmp, fn_r, fn_q);
        mod_exp_size = OSSL_FN_mod_exp_mont_ctx_size(fn_blindm, fn_blind,
            fn_tmp, fn_q, NULL);
        if (mod_mul_size == 0 || mod_exp_size == 0)
            goto release;
        fn_size = ((mod_mul_size > mod_exp_size) ? mod_mul_size : mod_exp_size)
            /* the body's own outer frame */
            + OSSL_FN_CTX_size(1, 0, 0);
        if (fn_size == 0)
            goto release;
        fn_ctx = OSSL_FN_CTX_secure_new_size(dsa->libctx, fn_size);
        if (fn_ctx == NULL)
            goto release;
        if ((token = OSSL_FN_CTX_start(fn_ctx)) == NULL)
            goto release;

        /*
         * Generate a blinding value
         * The size of q is tested in dsa_sign_setup() so there should not
         * be an infinite loop here.
         */
        do {
            if (!OSSL_FN_priv_rand(fn_blind, qbits - 1,
                    OSSL_FN_RAND_TOP_ANY, OSSL_FN_RAND_BOTTOM_ANY,
                    0, dsa->libctx))
                goto release;
        } while (OSSL_FN_is_zero(fn_blind));

        /* tmp := blind * priv_key * r mod q */
        if (!OSSL_FN_mod_mul(fn_tmp, fn_blind, fn_priv, fn_q, fn_ctx))
            goto release;
        if (!OSSL_FN_mod_mul(fn_tmp, fn_tmp, fn_r, fn_q, fn_ctx))
            goto release;

        /* blindm := blind * m mod q */
        if (!OSSL_FN_mod_mul(fn_blindm, fn_blind, fn_m, fn_q, fn_ctx))
            goto release;

        /* s := (blind * priv_key * r) + (blind * m) mod q */
        if (!OSSL_FN_mod_add_quick(fn_s, fn_tmp, fn_blindm, fn_q))
            goto release;

        /* s := s * k^-1 mod q */
        if (!OSSL_FN_mod_mul(fn_s, fn_s, fn_kinv, fn_q, fn_ctx))
            goto release;

        /*
         * blindm := blind^-1 = blind^(q-2) mod q, via Fermat's little
         * theorem and the constant-time modexp: q is prime and the
         * exponent is public, while OSSL_FN_mod_inverse() is not
         * constant-time w.r.t. its operand.  fn_tmp and fn_blindm are
         * both dead after the addition above, so fn_tmp serves as the
         * exponent scratch and fn_blindm as the result.
         */
        if (OSSL_FN_copy_truncate(fn_tmp, fn_q) == NULL
            || !OSSL_FN_sub_word(fn_tmp, 2))
            goto release;
        if (!OSSL_FN_mod_exp_mont(fn_blindm, fn_blind, fn_tmp, fn_q,
                fn_ctx, NULL))
            goto release;

        /* s := s * blind^-1 mod q */
        if (!OSSL_FN_mod_mul(fn_s, fn_s, fn_blindm, fn_q, fn_ctx))
            goto release;

        if (!OSSL_FN_CTX_end(fn_ctx, token)) {
            token = NULL;
            goto release;
        }
        token = NULL;

        /* Successful r and s get their significance-derived widths */
        fn_bits = (int)OSSL_FN_num_bits(fn_r);
        r_sz = fn_bits > 0 ? (fn_bits + BN_BITS2 - 1) / BN_BITS2 : 1;
        fn_bits = (int)OSSL_FN_num_bits(fn_s);
        s_sz = fn_bits > 0 ? (fn_bits + BN_BITS2 - 1) / BN_BITS2 : 1;
        fn_ok = 1;

    release:
        if (token != NULL)
            OSSL_FN_CTX_end(fn_ctx, token);
        token = NULL;
        OSSL_FN_CTX_free(fn_ctx);
        fn_ctx = NULL;

        /*
         * Restore the tops of the acquired values.  m, blind, blindm and
         * tmp are BN_CTX pool members, so this must happen on all paths
         * before the pool reclaims them.  bn_release() is NULL-safe in
         * the BIGNUM and its backing store, so acquisitions that never
         * happened need no guards.
         */
        bn_release(ret->r, r_sz);
        bn_release(ret->s, s_sz);
        bn_release(m, m_sz);
        bn_release(blind, blind_sz);
        bn_release(blindm, blindm_sz);
        bn_release(tmp, tmp_sz);
        if (!fn_ok)
            goto err;
    }

    /*
     * Redo if r or s is zero as required by FIPS 186-4: Section 4.6
     * This is very unlikely.
     * Limit the retries so there is no possibility of an infinite
     * loop for bad domain parameter values.
     */
    if (BN_is_zero(ret->r) || BN_is_zero(ret->s)) {
        if (retries++ > MAX_DSA_SIGN_RETRIES) {
            reason = DSA_R_TOO_MANY_RETRIES;
            goto err;
        }
        goto redo;
    }
    rv = 1;
err:
    if (rv == 0) {
        ERR_raise(ERR_LIB_DSA, reason);
        DSA_SIG_free(ret);
        ret = NULL;
    }
    BN_CTX_free(ctx);
    BN_clear_free(kinv);
    return ret;
}

static DSA_SIG *dsa_do_sign(const unsigned char *dgst, int dlen, DSA *dsa)
{
    return ossl_dsa_do_sign_int(dgst, dlen, dsa,
        0, NULL, NULL, NULL);
}

static int dsa_sign_setup_no_digest(DSA *dsa, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp)
{
    return dsa_sign_setup(dsa, ctx_in, kinvp, rp, NULL, 0,
        0, NULL, NULL, NULL);
}

static int dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in,
    BIGNUM **kinvp, BIGNUM **rp,
    const unsigned char *dgst, int dlen,
    unsigned int nonce_type, const char *digestname,
    OSSL_LIB_CTX *libctx, const char *propq)
{
    BN_CTX *ctx = NULL;
    BIGNUM *kinv = NULL, *r = *rp;
    OSSL_FN *k = NULL;
    const OSSL_FN *q = NULL, *priv = NULL;
    int ret = 0;
    int q_bits, qlimbs;
    /*
     * Used only when ((dsa)->meth->bn_mod_exp != NULL), but placed here
     * so err: code section can clean them up unconditionally
     */
    BIGNUM *bn_k = NULL, *bn_l = NULL;
    /* bn_release() widths; acquisition width set once qlimbs is known */
    int bn_k_sz = 1, bn_l_sz = 1;

    if (!dsa->params.p || !dsa->params.q || !dsa->params.g) {
        ERR_raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS);
        return 0;
    }

    /* Reject obviously invalid parameters */
    if (BN_is_zero(dsa->params.p)
        || BN_is_zero(dsa->params.q)
        || BN_is_zero(dsa->params.g)
        || BN_is_negative(dsa->params.p)
        || BN_is_negative(dsa->params.q)
        || BN_is_negative(dsa->params.g)) {
        ERR_raise(ERR_LIB_DSA, DSA_R_INVALID_PARAMETERS);
        return 0;
    }
    if (dsa->priv_key == NULL) {
        ERR_raise(ERR_LIB_DSA, DSA_R_MISSING_PRIVATE_KEY);
        return 0;
    }
    if (ctx_in == NULL) {
        /* if you don't pass in ctx_in you get a default libctx */
        if ((ctx = BN_CTX_new_ex(NULL)) == NULL)
            goto err;
    } else
        ctx = ctx_in;

    q_bits = BN_num_bits(dsa->params.q);
    if (q_bits < MIN_DSA_SIGN_QBITS)
        goto err;

    if ((q = bn_get_ossl_fn(dsa->params.q)) == NULL
        || (priv = bn_get_ossl_fn(dsa->priv_key)) == NULL)
        goto err;
    qlimbs = (int)ossl_fn_get_dsize(q);
    bn_k_sz = bn_l_sz = qlimbs + 1;

    if ((k = OSSL_FN_secure_new_limbs(qlimbs)) == NULL)
        goto err;

    /*
     * Get random k, fixed-width from the start, so there is no BIGNUM
     * top whose length could leak.
     */
    do {
        if (dgst != NULL) {
            if (nonce_type == 1) {
#ifndef FIPS_MODULE
                if (!ossl_fn_gen_deterministic_nonce_rfc6979(k,
                        dsa->params.q, priv,
                        dgst, dlen,
                        digestname,
                        libctx, propq))
#endif
                    goto err;
            } else {
                /*
                 * We calculate k from SHA512(private_key + H(message) + random).
                 * This protects the private key from a weak PRNG.
                 */
                if (!ossl_fn_gen_dsa_nonce(k, q, priv, dgst, dlen,
                        ossl_bn_get_libctx(ctx)))
                    goto err;
            }
        } else if (!OSSL_FN_priv_rand_range(k, q, 0,
                       ossl_bn_get_libctx(ctx)))
            goto err;
    } while (OSSL_FN_is_zero(k));

    /* Compute r = (g^k mod p) mod q */

    if ((dsa)->meth->bn_mod_exp != NULL) {
        OSSL_FN *fn_l, *fn_k;

        /*
         * The override receives BIGNUMs, so k is materialized, and gets
         * the fixed-length gymnastics: we do not want timing information
         * to leak the length of k, so we compute G^k using an equivalent
         * scalar of fixed bit-length.
         *
         * We unconditionally perform both of these additions to prevent a
         * small timing information leakage.  We then choose the sum that
         * is one bit longer than the modulus.
         *
         * There are some concerns about the efficacy of doing this.  More
         * specifically refer to the discussion starting with:
         *     https://github.com/openssl/openssl/pull/7486#discussion_r228323705
         * The fix is to rework BN so these gymnastics aren't required.
         *
         * The OSSL_FN path needs no such gymnastics: a fixed-width
         * exponent has no top that could leak its length.
         */
        bn_k = BN_new();
        bn_l = BN_new();
        if (bn_k == NULL || bn_l == NULL)
            goto err;
        BN_set_flags(bn_k, BN_FLG_CONSTTIME);
        BN_set_flags(bn_l, BN_FLG_CONSTTIME);

        /*
         * The additions and the choice between the sums are performed in
         * fixed-width OSSL_FN form, directly in the acquired views of
         * the two candidate BIGNUMs: on BIGNUMs their timing would depend
         * on the operands' tops, and a materialized k has a normalized
         * top (bn_release() corrects it), so the length of k would leak.
         */
        if ((fn_l = bn_acquire_ossl_fn(bn_l, qlimbs + 1)) == NULL
            || (fn_k = bn_acquire_ossl_fn(bn_k, qlimbs + 1)) == NULL
            || !OSSL_FN_add(fn_l, k, q)
            || !OSSL_FN_add(fn_k, fn_l, q)
            || !OSSL_FN_consttime_swap(OSSL_FN_is_bit_set(fn_l, q_bits),
                fn_k, fn_l))
            goto err;

        /*
         * The chosen sum, now in bn_k, has exactly q_bits + 1
         * significant bits, so the normalized top the override sees is
         * constant.
         */
        bn_release(bn_k, bn_k_sz);
        bn_release(bn_l, bn_l_sz);

        /*
         * External overrides may rely on receiving the warmed BN
         * Montgomery cache, as they did before the OSSL_FN conversion.
         */
        if (dsa->flags & DSA_FLAG_CACHE_MONT_P
            && !BN_MONT_CTX_set_locked(&dsa->method_mont_p,
                dsa->lock, dsa->params.p, ctx))
            goto err;

        if (!dsa->meth->bn_mod_exp(dsa, r, dsa->params.g, bn_k, dsa->params.p,
                ctx, dsa->method_mont_p))
            goto err;
    } else {
        if (!ossl_dsa_fn_mod_exp(dsa, r, dsa->params.g, k, dsa->params.p))
            goto err;
    }

    if (!BN_mod(r, r, dsa->params.q, ctx))
        goto err;

    /* Compute part of 's = inv(k) (m + xr) mod q' */
    if ((kinv = dsa_mod_inverse_fermat(k, dsa->params.q, ctx)) == NULL)
        goto err;

    BN_clear_free(*kinvp);
    *kinvp = kinv;
    kinv = NULL;
    ret = 1;
err:
    if (!ret)
        ERR_raise(ERR_LIB_DSA, ERR_R_BN_LIB);
    if (ctx != ctx_in)
        BN_CTX_free(ctx);
    /*
     * Restore the tops of bn_k and bn_l if they were acquired; a second
     * release after the hook-path release above is idempotent, and
     * bn_release() is NULL-safe, so this needs no guards.
     */
    bn_release(bn_k, bn_k_sz);
    bn_release(bn_l, bn_l_sz);
    BN_clear_free(bn_k);
    BN_clear_free(bn_l);
    OSSL_FN_clear_free(k);
    return ret;
}

static int dsa_do_verify(const unsigned char *dgst, int dgst_len,
    DSA_SIG *sig, DSA *dsa)
{
    BN_CTX *ctx;
    BIGNUM *u1, *u2, *t1;
    BN_MONT_CTX *mont = NULL;
    const BIGNUM *r, *s;
    int ret = -1, i;

    if (dsa->params.p == NULL
        || dsa->params.q == NULL
        || dsa->params.g == NULL) {
        ERR_raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS);
        return -1;
    }

    i = BN_num_bits(dsa->params.q);
    /* fips 186-3 allows only different sizes for q */
    if (i != 160 && i != 224 && i != 256) {
        ERR_raise(ERR_LIB_DSA, DSA_R_BAD_Q_VALUE);
        return -1;
    }

    if (BN_num_bits(dsa->params.p) > OPENSSL_DSA_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DSA, DSA_R_MODULUS_TOO_LARGE);
        return -1;
    }
    u1 = BN_new();
    u2 = BN_new();
    t1 = BN_new();
    ctx = BN_CTX_new_ex(NULL); /* verify does not need a libctx */
    if (u1 == NULL || u2 == NULL || t1 == NULL || ctx == NULL)
        goto err;

    DSA_SIG_get0(sig, &r, &s);

    if (BN_is_zero(r) || BN_is_negative(r) || BN_ucmp(r, dsa->params.q) >= 0) {
        ret = 0;
        goto err;
    }
    if (BN_is_zero(s) || BN_is_negative(s) || BN_ucmp(s, dsa->params.q) >= 0) {
        ret = 0;
        goto err;
    }

    /*
     * Calculate W = inv(S) mod Q save W in u2
     */
    if ((BN_mod_inverse(u2, s, dsa->params.q, ctx)) == NULL)
        goto err;

    /* save M in u1 */
    if (dgst_len > (i >> 3))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dgst_len = (i >> 3);
    if (BN_bin2bn(dgst, dgst_len, u1) == NULL)
        goto err;

    /* u1 = M * w mod q */
    if (!BN_mod_mul(u1, u1, u2, dsa->params.q, ctx))
        goto err;

    /* u2 = r * w mod q */
    if (!BN_mod_mul(u2, r, u2, dsa->params.q, ctx))
        goto err;

    if (dsa->flags & DSA_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dsa->method_mont_p,
            dsa->lock, dsa->params.p, ctx);
        if (!mont)
            goto err;
    }

    if (dsa->meth->dsa_mod_exp != NULL) {
        if (!dsa->meth->dsa_mod_exp(dsa, t1, dsa->params.g, u1, dsa->pub_key, u2,
                dsa->params.p, ctx, mont))
            goto err;
    } else {
        if (!BN_mod_exp2_mont(t1, dsa->params.g, u1, dsa->pub_key, u2,
                dsa->params.p, ctx, mont))
            goto err;
    }

    /* let u1 = u1 mod q */
    if (!BN_mod(u1, t1, dsa->params.q, ctx))
        goto err;

    /*
     * V is now in u1.  If the signature is correct, it will be equal to R.
     */
    ret = (BN_ucmp(u1, r) == 0);

err:
    if (ret < 0)
        ERR_raise(ERR_LIB_DSA, ERR_R_BN_LIB);
    BN_CTX_free(ctx);
    BN_free(u1);
    BN_free(u2);
    BN_free(t1);
    return ret;
}

static int dsa_init(DSA *dsa)
{
    dsa->flags |= DSA_FLAG_CACHE_MONT_P;
    dsa->dirty_cnt++;
    return 1;
}

static int dsa_finish(DSA *dsa)
{
    BN_MONT_CTX_free(dsa->method_mont_p);
    dsa->method_mont_p = NULL;
    OSSL_FN_MONT_CTX_free(dsa->method_mont_fn_p);
    dsa->method_mont_fn_p = NULL;
    return 1;
}

/*
 * The OSSL_FN modular exponentiation backing the default DSA_METHOD's
 * private-key calculations.  The exponent arrives in OSSL_FN form; the
 * remaining BIGNUM operands are passed as views, the writable result is
 * acquired at the modulus width before OSSL_FN_CTX sizing, and the
 * OSSL_FN_CTX arena is explicitly sized from the operation's sizing
 * companion.
 */
int ossl_dsa_fn_mod_exp(const DSA *dsa, BIGNUM *r,
    const BIGNUM *a, const OSSL_FN *p,
    const BIGNUM *m)
{
    int ret = 0;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN_MONT_CTX *fn_mont = NULL;
    OSSL_FN *fn_r = NULL;
    const OSSL_FN *fn_a = NULL, *fn_p = p, *fn_m = NULL;
    int limbs, fn_bits;
    int r_sz; /* bn_release() width; full width until success is known */
    size_t fn_size;

    fn_a = bn_get_ossl_fn(a);
    fn_m = bn_get_ossl_fn(m);
    if (fn_a == NULL || fn_p == NULL || fn_m == NULL)
        return 0;
    limbs = (int)ossl_fn_get_dsize(fn_m);

    /* Acquire the writable result before OSSL_FN_CTX sizing. */
    if ((fn_r = bn_acquire_ossl_fn(r, limbs)) == NULL)
        return 0;
    r_sz = limbs;

    if (dsa->flags & DSA_FLAG_CACHE_MONT_P) {
        /*
         * We take the input DSA as const, but we lie, because in some cases
         * we want to get a hold of its Montgomery context.
         *
         * We cast to remove the const qualifier in this case, it should be
         * fine...
         */
        OSSL_FN_MONT_CTX **pmont
            = (OSSL_FN_MONT_CTX **)&dsa->method_mont_fn_p;

        fn_mont = OSSL_FN_MONT_CTX_set_locked(pmont, dsa->lock, fn_m);
        if (fn_mont == NULL)
            goto err;
    }

    fn_size = OSSL_FN_mod_exp_mont_ctx_size(fn_r, fn_a, fn_p, fn_m, fn_mont);
    if (fn_size == 0)
        goto err;

    fn_ctx = OSSL_FN_CTX_secure_new_size(dsa->libctx, fn_size);
    if (fn_ctx == NULL)
        goto err;
    /*
     * No OSSL_FN_CTX_start() here: OSSL_FN_mod_exp_mont_ctx_size()
     * budgets the callee's frames, not a caller frame.
     */
    ret = OSSL_FN_mod_exp_mont(fn_r, fn_a, fn_p, fn_m, fn_ctx, fn_mont);

    if (ret) {
        fn_bits = (int)OSSL_FN_num_bits(fn_r);
        r_sz = (fn_bits > 0) ? (fn_bits + BN_BITS2 - 1) / BN_BITS2 : 1;
    }
err:
    bn_release(r, r_sz);
    OSSL_FN_CTX_free(fn_ctx);
    return ret;
}

/*
 * Compute the inverse of k modulo q.
 * Since q is prime, Fermat's Little Theorem applies, which reduces this to
 * mod-exp operation.  Both the exponent and modulus are public information
 * so a mod-exp that doesn't leak the base is sufficient.  A newly allocated
 * BIGNUM is returned which the caller must free.
 */
static BIGNUM *dsa_mod_inverse_fermat(const OSSL_FN *k, const BIGNUM *q,
    BN_CTX *ctx)
{
    BIGNUM *res = NULL;
    BIGNUM *r = NULL, *e;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN_MONT_CTX *fn_mont = NULL;
    const OSSL_FN *fn_q = NULL;
    OSSL_FN *fn_r = NULL, *fn_e = NULL;
    size_t fn_size;
    int qlimbs, fn_bits;
    int ok = 0;
    /* bn_release() widths; full width until success is known */
    int r_sz, e_sz;

    if ((fn_q = bn_get_ossl_fn(q)) == NULL)
        return NULL;
    qlimbs = (int)ossl_fn_get_dsize(fn_q);
    r_sz = e_sz = qlimbs;

    if ((r = BN_new()) == NULL)
        return NULL;

    BN_CTX_start(ctx);
    if ((e = BN_CTX_get(ctx)) == NULL)
        goto err;

    /*
     * The exponent e = q - 2 is public; the base k is secret.  Acquire the
     * writable results before the OSSL_FN_CTX sizing, which derives from
     * their allocated widths.
     */
    if ((fn_r = bn_acquire_ossl_fn(r, qlimbs)) == NULL
        || (fn_e = bn_acquire_ossl_fn(e, qlimbs)) == NULL)
        goto err;

    if (OSSL_FN_copy_truncate(fn_e, fn_q) == NULL
        || !OSSL_FN_sub_word(fn_e, 2))
        goto err;

    /*
     * The Montgomery context for q is local to this function, never the
     * key's cached context for p.
     */
    if ((fn_mont = OSSL_FN_MONT_CTX_new(fn_q)) == NULL)
        goto err;

    fn_size = OSSL_FN_mod_exp_mont_ctx_size(fn_r, k, fn_e, fn_q, fn_mont);
    if (fn_size == 0)
        goto err;

    fn_ctx = OSSL_FN_CTX_secure_new_size(ossl_bn_get_libctx(ctx), fn_size);
    if (fn_ctx == NULL)
        goto err;
    /*
     * No OSSL_FN_CTX_start() here: OSSL_FN_mod_exp_mont_ctx_size()
     * budgets the callee's frames, not a caller frame.
     */
    if (OSSL_FN_mod_exp_mont(fn_r, k, fn_e, fn_q, fn_ctx, fn_mont)) {
        fn_bits = (int)OSSL_FN_num_bits(fn_r);
        r_sz = fn_bits > 0 ? (fn_bits + BN_BITS2 - 1) / BN_BITS2 : 1;
        ok = 1;
    }
err:
    /*
     * e is a BN_CTX pool member, so its top must be restored on all
     * paths before BN_CTX_end() returns it to the pool.  bn_release()
     * is NULL-safe in the BIGNUM and its backing store, so acquisitions
     * that never happened need no guards.
     */
    bn_release(r, r_sz);
    bn_release(e, e_sz);
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_MONT_CTX_free(fn_mont);
    BN_CTX_end(ctx);
    if (ok)
        res = r;
    else
        BN_clear_free(r); /* may hold a partially computed secret inverse */
    return res;
}
