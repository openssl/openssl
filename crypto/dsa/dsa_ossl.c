/*
 * Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/fsn.h"
#include "crypto/fsn_intern.h"
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
static BIGNUM *dsa_mod_inverse_fermat(const OSSL_FSN *k, const BIGNUM *q,
    BN_CTX *ctx);
static int ossl_dsa_fsn_mod_exp(const DSA *dsa, BIGNUM *r,
    const BIGNUM *a, const OSSL_FSN *p,
    const BIGNUM *m);

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
        const OSSL_FSN *fsn_kinv = NULL, *fsn_q = NULL, *fsn_priv = NULL;
        const OSSL_FSN *fsn_r_in = NULL;
        OSSL_FSN *fsn_r = NULL, *fsn_s = NULL, *fsn_m = NULL;
        OSSL_FSN *fsn_blind = NULL, *fsn_blindm = NULL, *fsn_tmp = NULL;
        OSSL_FSN_CTX *fsn_ctx = NULL;
        size_t fsn_size;
        int qbits, qlimbs;
        int fsn_ok = 0;

        fsn_q = bn_get_ossl_fsn(dsa->params.q);
        fsn_priv = bn_get_ossl_fsn(dsa->priv_key);
        fsn_kinv = bn_get_ossl_fsn(kinv);
        fsn_r_in = bn_get_ossl_fsn(ret->r);
        if (fsn_q == NULL || fsn_priv == NULL || fsn_kinv == NULL
            || fsn_r_in == NULL)
            goto err;

        qbits = BN_num_bits(dsa->params.q);
        /* Same width convention as dsa_sign_setup(): the view width of q */
        qlimbs = (int)ossl_fsn_get_dsize(fsn_q);

        /*
         * r is read-only in this body, and arrives with the p width of
         * the modexp that produced it.  It is copied into a q-wide
         * temporary (value-preserving, as r < q) to keep the modular
         * arithmetic below at the q width.  r is public, so a plain
         * allocation suffices.
         */
        if ((fsn_r = OSSL_FSN_new_limbs(qlimbs)) == NULL)
            goto err;
        OSSL_FSN_copy_truncate(fsn_r, fsn_r_in);

        /*
         * Acquire the writable values at the q width before the
         * OSSL_FSN_CTX sizing, which derives from their allocated widths.
         * TODO(FIXNUM): m is read-only here and can become a
         * bn_get_ossl_fsn() view once that yields a valid view for a
         * zero BIGNUM.
         */
        if ((fsn_s = bn_acquire_ossl_fsn(ret->s, qlimbs)) == NULL
            || (fsn_m = bn_acquire_ossl_fsn(m, qlimbs)) == NULL
            || (fsn_blind = bn_acquire_ossl_fsn(blind, qlimbs)) == NULL
            || (fsn_blindm = bn_acquire_ossl_fsn(blindm, qlimbs)) == NULL
            || (fsn_tmp = bn_acquire_ossl_fsn(tmp, qlimbs)) == NULL)
            goto release;

        /*
         * Each operation pops its arena frame when done, so sequential
         * operations reuse the space: the arena needs room for the
         * largest single operation.  No body frame is started: the
         * operations start their own frames, and this body allocates
         * nothing from the arena.
         */
        fsn_size = OSSL_FSN_mod_mul_ctx_size_from_nums(
            fsn_tmp, fsn_blind, fsn_priv, fsn_q);
        fsn_size = ossl_fsn_ctx_max_size(fsn_size,
            OSSL_FSN_mod_mul_ctx_size_from_nums(fsn_tmp, fsn_tmp, fsn_r, fsn_q));
        fsn_size = ossl_fsn_ctx_max_size(fsn_size,
            OSSL_FSN_mod_mul_ctx_size_from_nums(
                fsn_blindm, fsn_blind, fsn_m, fsn_q));
        fsn_size = ossl_fsn_ctx_max_size(fsn_size,
            OSSL_FSN_mod_mul_ctx_size_from_nums(fsn_s, fsn_s, fsn_kinv, fsn_q));
        fsn_size = ossl_fsn_ctx_max_size(fsn_size,
            OSSL_FSN_mod_mul_ctx_size_from_nums(fsn_s, fsn_s, fsn_blindm, fsn_q));
        fsn_size = ossl_fsn_ctx_max_size(fsn_size,
            OSSL_FSN_mod_inverse_prime_ctx_size_from_nums(
                fsn_blindm, fsn_blind, fsn_q, NULL));
        if (fsn_size == 0)
            goto release;
        /* TODO(FIXNUM): a secure arena is a possible future consideration */
        fsn_ctx = OSSL_FSN_CTX_new_size(dsa->libctx, fsn_size);
        if (fsn_ctx == NULL)
            goto release;

        /*
         * Generate a blinding value
         * The size of q is tested in dsa_sign_setup() so there should not
         * be an infinite loop here.
         */
        do {
            if (!OSSL_FSN_priv_rand(fsn_blind, qbits - 1,
                    OSSL_FSN_RAND_TOP_ANY, OSSL_FSN_RAND_BOTTOM_ANY,
                    0, dsa->libctx))
                goto release;
        } while (OSSL_FSN_is_zero(fsn_blind));

        /* tmp := blind * priv_key * r mod q */
        if (!OSSL_FSN_mod_mul(fsn_tmp, fsn_blind, fsn_priv, fsn_q, fsn_ctx))
            goto release;
        if (!OSSL_FSN_mod_mul(fsn_tmp, fsn_tmp, fsn_r, fsn_q, fsn_ctx))
            goto release;

        /* blindm := blind * m mod q */
        if (!OSSL_FSN_mod_mul(fsn_blindm, fsn_blind, fsn_m, fsn_q, fsn_ctx))
            goto release;

        /* s := (blind * priv_key * r) + (blind * m) mod q */
        if (!OSSL_FSN_mod_add_quick(fsn_s, fsn_tmp, fsn_blindm, fsn_q))
            goto release;

        /* s := s * k^-1 mod q */
        if (!OSSL_FSN_mod_mul(fsn_s, fsn_s, fsn_kinv, fsn_q, fsn_ctx))
            goto release;

        /*
         * blindm := blind^-1 mod q.  q is prime, so the constant-time
         * Fermat inverse applies, with the public exponent derived from
         * q internally; OSSL_FSN_mod_inverse() is not constant-time
         * w.r.t. its operand.
         */
        if (!OSSL_FSN_mod_inverse_prime(fsn_blindm, fsn_blind, fsn_q, fsn_ctx,
                NULL))
            goto release;

        /* s := s * blind^-1 mod q */
        if (!OSSL_FSN_mod_mul(fsn_s, fsn_s, fsn_blindm, fsn_q, fsn_ctx))
            goto release;

        fsn_ok = 1;

    release:
        OSSL_FSN_CTX_free(fsn_ctx);
        fsn_ctx = NULL;
        OSSL_FSN_free(fsn_r);
        fsn_r = NULL;

        /*
         * Restore the tops of the acquired values; bn_release() corrects
         * the top itself, making the released width moot.  m, blind,
         * blindm and tmp are BN_CTX pool members, so this must happen on
         * all paths before the pool reclaims them.  bn_release() is
         * NULL-safe in the BIGNUM and its backing store, so acquisitions
         * that never happened need no guards.
         */
        bn_release(ret->s, qlimbs);
        bn_release(m, qlimbs);
        bn_release(blind, qlimbs);
        bn_release(blindm, qlimbs);
        bn_release(tmp, qlimbs);
        if (!fsn_ok)
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
    OSSL_FSN *k = NULL;
    const OSSL_FSN *q = NULL, *priv = NULL;
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

    if ((q = bn_get_ossl_fsn(dsa->params.q)) == NULL
        || (priv = bn_get_ossl_fsn(dsa->priv_key)) == NULL)
        goto err;
    qlimbs = (int)ossl_fsn_get_dsize(q);
    bn_k_sz = bn_l_sz = qlimbs + 1;

    if ((k = OSSL_FSN_secure_new_limbs(qlimbs)) == NULL)
        goto err;

    /*
     * Get random k, fixed-width from the start, so there is no BIGNUM
     * top whose length could leak.
     */
    do {
        if (dgst != NULL) {
            if (nonce_type == 1) {
#ifndef FIPS_MODULE
                if (!ossl_fsn_gen_deterministic_nonce_rfc6979(k,
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
                if (!ossl_fsn_gen_dsa_nonce(k, q, priv, dgst, dlen,
                        ossl_bn_get_libctx(ctx)))
                    goto err;
            }
        } else if (!OSSL_FSN_priv_rand_range(k, q, 0,
                       ossl_bn_get_libctx(ctx)))
            goto err;
    } while (OSSL_FSN_is_zero(k));

    /* Compute r = (g^k mod p) mod q */

    if ((dsa)->meth->bn_mod_exp != NULL) {
        OSSL_FSN *fsn_l, *fsn_k;

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
         * The OSSL_FSN path needs no such gymnastics: a fixed-width
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
         * fixed-width OSSL_FSN form, directly in the acquired views of
         * the two candidate BIGNUMs: on BIGNUMs their timing would depend
         * on the operands' tops, and a materialized k has a normalized
         * top (bn_release() corrects it), so the length of k would leak.
         */
        if ((fsn_l = bn_acquire_ossl_fsn(bn_l, qlimbs + 1)) == NULL
            || (fsn_k = bn_acquire_ossl_fsn(bn_k, qlimbs + 1)) == NULL
            || !OSSL_FSN_add(fsn_l, k, q)
            || !OSSL_FSN_add(fsn_k, fsn_l, q)
            || !OSSL_FSN_consttime_swap(OSSL_FSN_is_bit_set(fsn_l, q_bits),
                fsn_k, fsn_l))
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
         * Montgomery cache, as they did before the OSSL_FSN conversion.
         */
        if (dsa->flags & DSA_FLAG_CACHE_MONT_P
            && !BN_MONT_CTX_set_locked(&dsa->method_mont_p,
                dsa->lock, dsa->params.p, ctx))
            goto err;

        if (!dsa->meth->bn_mod_exp(dsa, r, dsa->params.g, bn_k, dsa->params.p,
                ctx, dsa->method_mont_p))
            goto err;
    } else {
        if (!ossl_dsa_fsn_mod_exp(dsa, r, dsa->params.g, k, dsa->params.p))
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
    OSSL_FSN_clear_free(k);
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
    OSSL_FSN_MONT_CTX_free(dsa->method_mont_fsn_p);
    dsa->method_mont_fsn_p = NULL;
    return 1;
}

/**
 * Compute r = a^p mod m with OSSL_FSN, for the default DSA_METHOD's
 * private-key calculations.  The exponent arrives in OSSL_FSN form; the
 * remaining BIGNUM operands are passed as views, the writable result is
 * acquired at the modulus width before OSSL_FSN_CTX sizing, and the
 * OSSL_FSN_CTX arena is explicitly sized from the operation's sizing
 * companion.
 *
 * @param[in]   dsa     The key; with DSA_FLAG_CACHE_MONT_P set, its cached
 *                      Montgomery context for |m| is used.
 * @param[out]  r       The result, as wide as |m|.
 * @param[in]   a       The base.
 * @param[in]   p       The secret exponent.
 * @param[in]   m       The modulus.
 * @returns             1 on success, 0 on error.
 */
static int ossl_dsa_fsn_mod_exp(const DSA *dsa, BIGNUM *r,
    const BIGNUM *a, const OSSL_FSN *p,
    const BIGNUM *m)
{
    int ret = 0;
    OSSL_FSN_CTX *fsn_ctx = NULL;
    OSSL_FSN_MONT_CTX *fsn_mont = NULL;
    OSSL_FSN *fsn_r = NULL;
    const OSSL_FSN *fsn_a = NULL, *fsn_p = p, *fsn_m = NULL;
    int limbs;
    size_t fsn_size;

    fsn_a = bn_get_ossl_fsn(a);
    fsn_m = bn_get_ossl_fsn(m);
    if (fsn_a == NULL || fsn_p == NULL || fsn_m == NULL)
        return 0;
    limbs = (int)ossl_fsn_get_dsize(fsn_m);

    /* Acquire the writable result before OSSL_FSN_CTX sizing. */
    if ((fsn_r = bn_acquire_ossl_fsn(r, limbs)) == NULL)
        return 0;

    if (dsa->flags & DSA_FLAG_CACHE_MONT_P) {
        /*
         * We take the input DSA as const, but we lie, because in some cases
         * we want to get a hold of its Montgomery context.
         *
         * We cast to remove the const qualifier in this case, it should be
         * fine...
         */
        OSSL_FSN_MONT_CTX **pmont
            = (OSSL_FSN_MONT_CTX **)&dsa->method_mont_fsn_p;

        fsn_mont = OSSL_FSN_MONT_CTX_set_locked(pmont, dsa->lock, fsn_m);
        if (fsn_mont == NULL)
            goto err;
    }

    fsn_size = OSSL_FSN_mod_exp_mont_ctx_size_from_nums(
        fsn_r, fsn_a, fsn_p, fsn_m, fsn_mont);
    if (fsn_size == 0)
        goto err;

    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fsn_ctx = OSSL_FSN_CTX_new_size(dsa->libctx, fsn_size);
    if (fsn_ctx == NULL)
        goto err;
    /*
     * No OSSL_FSN_CTX_start() here: OSSL_FSN_mod_exp_mont_ctx_size_from_nums()
     * budgets the callee's frames, not a caller frame.
     */
    ret = OSSL_FSN_mod_exp_mont(fsn_r, fsn_a, fsn_p, fsn_m, fsn_ctx, fsn_mont);

err:
    /* bn_release() corrects the top, making the released width moot */
    bn_release(r, limbs);
    OSSL_FSN_CTX_free(fsn_ctx);
    return ret;
}

/**
 * Compute the inverse of k modulo q.
 * Since q is prime, Fermat's Little Theorem applies, which
 * OSSL_FSN_mod_inverse_prime() exploits: the exponent it derives from q
 * is public, so a mod-exp that doesn't leak the base is sufficient.
 *
 * @param[in]   k       The secret nonce to invert.
 * @param[in]   q       The prime subgroup order.
 * @param[in]   ctx     The BIGNUM context, used for its library context.
 * @returns             A newly allocated BIGNUM holding k^-1 mod q, which
 *                      the caller must free, or NULL on error.
 */
static BIGNUM *dsa_mod_inverse_fermat(const OSSL_FSN *k, const BIGNUM *q,
    BN_CTX *ctx)
{
    BIGNUM *res = NULL;
    BIGNUM *r = NULL;
    OSSL_FSN_CTX *fsn_ctx = NULL;
    const OSSL_FSN *fsn_q = NULL;
    OSSL_FSN *fsn_r = NULL;
    size_t fsn_size;
    int qlimbs;
    int ok = 0;

    if ((fsn_q = bn_get_ossl_fsn(q)) == NULL)
        return NULL;
    qlimbs = (int)ossl_fsn_get_dsize(fsn_q);

    if ((r = BN_new()) == NULL)
        return NULL;

    /*
     * The base k is secret.  Acquire the writable result before the
     * OSSL_FSN_CTX sizing, which derives from its allocated width.
     */
    if ((fsn_r = bn_acquire_ossl_fsn(r, qlimbs)) == NULL)
        goto err;

    fsn_size = OSSL_FSN_mod_inverse_prime_ctx_size_from_nums(fsn_r, k, fsn_q, NULL);
    if (fsn_size == 0)
        goto err;

    /* TODO(FIXNUM): a secure arena is a possible future consideration */
    fsn_ctx = OSSL_FSN_CTX_new_size(ossl_bn_get_libctx(ctx), fsn_size);
    if (fsn_ctx == NULL)
        goto err;
    /*
     * No OSSL_FSN_CTX_start() here:
     * OSSL_FSN_mod_inverse_prime_ctx_size_from_nums() budgets the callee's
     * frames, not a caller frame.
     */
    if (OSSL_FSN_mod_inverse_prime(fsn_r, k, fsn_q, fsn_ctx, NULL))
        ok = 1;
err:
    /* bn_release() corrects the top, making the released width moot */
    bn_release(r, qlimbs);
    OSSL_FSN_CTX_free(fsn_ctx);
    if (ok)
        res = r;
    else
        BN_clear_free(r); /* may hold a partially computed secret inverse */
    return res;
}
