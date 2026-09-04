/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include "dh_local.h"
#include "crypto/bn.h"
#include "crypto/dh.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "crypto/security_bits.h"

#ifdef FIPS_MODULE
#define MIN_STRENGTH 112
#else
#define MIN_STRENGTH 80
#endif

static int generate_key(DH *dh);
static int dh_bn_mod_exp(const DH *dh, BIGNUM *r,
    const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
static int dh_init(DH *dh);
static int dh_finish(DH *dh);

/*
 * See SP800-56Ar3 Section 5.7.1.1
 * Finite Field Cryptography Diffie-Hellman (FFC DH) Primitive
 */
int ossl_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    BN_CTX *ctx = NULL;
    BIGNUM *z = NULL, *pminus1;
    int ret = -1;

    if (BN_num_bits(dh->params.p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        goto err;
    }

    if (dh->params.q != NULL
        && BN_num_bits(dh->params.q) > OPENSSL_DH_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_Q_TOO_LARGE);
        goto err;
    }

    if (BN_num_bits(dh->params.p) < DH_MIN_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        return 0;
    }

    ctx = BN_CTX_new_ex(dh->libctx);
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    pminus1 = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);
    if (z == NULL)
        goto err;

    if (dh->priv_key == NULL) {
        ERR_raise(ERR_LIB_DH, DH_R_NO_PRIVATE_VALUE);
        goto err;
    }

    /* (Step 1) Z = pub_key^priv_key mod p */
    if (!dh->meth->bn_mod_exp(dh, z, pub_key, dh->priv_key, dh->params.p, ctx,
            NULL)) {
        ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);
        goto err;
    }

    /* (Step 2) Error if z <= 1 or z = p - 1 */
    if (BN_copy(pminus1, dh->params.p) == NULL
        || !BN_sub_word(pminus1, 1)
        || BN_cmp(z, BN_value_one()) <= 0
        || BN_cmp(z, pminus1) == 0) {
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_SECRET);
        goto err;
    }

    /* return the padded key, i.e. same number of bytes as the modulus */
    ret = BN_bn2binpad(z, key, BN_num_bytes(dh->params.p));
err:
    BN_clear(z); /* (Step 2) destroy intermediate values */
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

/*-
 * NB: This function is inherently not constant time due to the
 * RFC 5246 (8.1.2) padding style that strips leading zero bytes.
 */
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    int ret = 0, i;
    volatile int npad = 0, mask = 1;

    /* compute the key; ret is constant unless compute_key is external */
#ifdef FIPS_MODULE
    ret = ossl_dh_compute_key(key, pub_key, dh);
#else
    ret = dh->meth->compute_key(key, pub_key, dh);
#endif
    if (ret <= 0)
        return ret;

    /* count leading zero bytes, yet still touch all bytes */
    for (i = 0; i < ret; i++) {
        mask &= !key[i];
        npad += mask;
    }

    /* unpad key */
    ret -= npad;
    /* key-dependent memory access, potentially leaking npad / ret */
    memmove(key, key + npad, ret);
    /* key-dependent memory access, potentially leaking npad / ret */
    memset(key + ret, 0, npad);

    return ret;
}

int DH_compute_key_padded(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
    int rv, pad;

    /* rv is constant unless compute_key is external */
#ifdef FIPS_MODULE
    rv = ossl_dh_compute_key(key, pub_key, dh);
#else
    rv = dh->meth->compute_key(key, pub_key, dh);
#endif
    if (rv <= 0)
        return rv;
    pad = BN_num_bytes(dh->params.p) - rv;
    /* pad is constant (zero) unless compute_key is external */
    if (pad > 0) {
        memmove(key + pad, key, rv);
        memset(key, 0, pad);
    }
    return rv + pad;
}

static DH_METHOD dh_ossl = {
    "OpenSSL DH Method",
    generate_key,
    ossl_dh_compute_key,
    dh_bn_mod_exp,
    dh_init,
    dh_finish,
    DH_FLAG_FIPS_METHOD,
    NULL,
    NULL
};

static const DH_METHOD *default_DH_method = &dh_ossl;

const DH_METHOD *DH_OpenSSL(void)
{
    return &dh_ossl;
}

const DH_METHOD *DH_get_default_method(void)
{
    return default_DH_method;
}

/*
 * The OSSL_FN modular exponentiation backing the default
 * DH_METHOD::bn_mod_exp implementation; see dh_bn_mod_exp().
 */
static int dh_ossl_fn_mod_exp(const DH *dh, BIGNUM *r,
    const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m)
{
    int ret = 0;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN_MONT_CTX *fn_mont = NULL;
    OSSL_FN *fn_r = NULL;
    const OSSL_FN *fn_a = NULL, *fn_p = NULL, *fn_m = NULL;
    const void *token = NULL;
    int limbs, fn_bits;
    size_t fn_size;

    fn_a = bn_get_ossl_fn(a);
    fn_p = bn_get_ossl_fn(p);
    fn_m = bn_get_ossl_fn(m);
    if (fn_a == NULL || fn_p == NULL || fn_m == NULL)
        return 0;
    limbs = (int)ossl_fn_get_dsize(fn_m);

    /* Acquire the writable result before OSSL_FN_CTX sizing. */
    if ((fn_r = bn_acquire_ossl_fn(r, limbs)) == NULL)
        return 0;

    if (dh->flags & DH_FLAG_CACHE_MONT_P) {
        /*
         * We take the input DH as const, but we lie, because in some cases we
         * want to get a hold of its Montgomery context.
         *
         * We cast to remove the const qualifier in this case, it should be
         * fine...
         */
        OSSL_FN_MONT_CTX **pmont = (OSSL_FN_MONT_CTX **)&dh->method_mont_fn_p;

        fn_mont = OSSL_FN_MONT_CTX_set_locked(pmont, dh->lock, fn_m);
        if (fn_mont == NULL)
            goto err;
    }

    fn_size = OSSL_FN_mod_exp_mont_ctx_size(fn_r, fn_a, fn_p, fn_m, fn_mont);
    if (fn_size == 0)
        goto err;

    fn_ctx = OSSL_FN_CTX_secure_new_size(dh->libctx, fn_size);
    if (fn_ctx == NULL)
        goto err;
    if ((token = OSSL_FN_CTX_start(fn_ctx)) == NULL)
        goto err;

    ret = OSSL_FN_mod_exp_mont(fn_r, fn_a, fn_p, fn_m, fn_ctx, fn_mont);

    if (ret) {
        fn_bits = (int)OSSL_FN_num_bits(fn_r);
        bn_release(r, fn_bits > 0 ? (fn_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
    }

    if (!OSSL_FN_CTX_end(fn_ctx, token)) {
        token = NULL;
        goto err;
    }
    token = NULL;
err:
    if (token != NULL)
        OSSL_FN_CTX_end(fn_ctx, token);
    OSSL_FN_CTX_free(fn_ctx);
    return ret;
}

/*
 * The default DH_METHOD::bn_mod_exp implementation.  This is where the
 * default method's BIGNUM -> OSSL_FN conversion happens; see
 * dh_ossl_fn_mod_exp() above.
 *
 * On s390x, the hardware accelerated s390x_mod_exp() is tried first and
 * the OSSL_FN path serves as its fallback, mirroring the role
 * BN_mod_exp_mont() had before.
 *
 * Keeping the OSSL_FN conversion behind this hook means surgical
 * overrides (DH_meth_set_bn_mod_exp()) keep being honored by the default
 * method's compute_key / generate_key operations.
 */
static int dh_bn_mod_exp(const DH *dh, BIGNUM *r,
    const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
#ifdef S390X_MOD_EXP
    if (s390x_mod_exp(r, a, p, m, ctx, m_ctx))
        return 1;
#endif
    return dh_ossl_fn_mod_exp(dh, r, a, p, m);
}

static int dh_init(DH *dh)
{
    dh->flags |= DH_FLAG_CACHE_MONT_P;
    dh->dirty_cnt++;
    return 1;
}

static int dh_finish(DH *dh)
{
    BN_MONT_CTX_free(dh->method_mont_p);
    dh->method_mont_p = NULL;
    OSSL_FN_MONT_CTX_free(dh->method_mont_fn_p);
    dh->method_mont_fn_p = NULL;
    return 1;
}

#ifndef FIPS_MODULE
void DH_set_default_method(const DH_METHOD *meth)
{
    default_DH_method = meth;
}
#endif /* FIPS_MODULE */

int DH_generate_key(DH *dh)
{
#ifdef FIPS_MODULE
    return generate_key(dh);
#else
    return dh->meth->generate_key(dh);
#endif
}

int ossl_dh_generate_public_key(BN_CTX *ctx, const DH *dh,
    const BIGNUM *priv_key, BIGNUM *pub_key)
{
    return dh->meth->bn_mod_exp(dh, pub_key, dh->params.g, priv_key,
        dh->params.p, ctx, NULL);
}

static int generate_key(DH *dh)
{
    int ok = 0;
    int generate_new_key = 0;
#ifndef FIPS_MODULE
    int l;
#endif
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if (BN_num_bits(dh->params.p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE);
        return 0;
    }

    if (dh->params.q != NULL
        && BN_num_bits(dh->params.q) > OPENSSL_DH_MAX_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_Q_TOO_LARGE);
        return 0;
    }

    if (BN_num_bits(dh->params.p) < DH_MIN_MODULUS_BITS) {
        ERR_raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL);
        return 0;
    }

    ctx = BN_CTX_new_ex(dh->libctx);
    if (ctx == NULL)
        goto err;

    if (dh->priv_key == NULL) {
        priv_key = BN_secure_new();
        if (priv_key == NULL)
            goto err;
        generate_new_key = 1;
    } else {
        priv_key = dh->priv_key;
    }

    if (dh->pub_key == NULL) {
        pub_key = BN_new();
        if (pub_key == NULL)
            goto err;
    } else {
        pub_key = dh->pub_key;
    }
    if (generate_new_key) {
        /* Is it an approved safe prime ?*/
        if (DH_get_nid(dh) != NID_undef) {
            int max_strength = ossl_ifc_ffc_compute_security_bits(BN_num_bits(dh->params.p));

            if (dh->params.q == NULL
                || dh->length > BN_num_bits(dh->params.q))
                goto err;
            /* dh->length = maximum bit length of generated private key */
            if (!ossl_ffc_generate_private_key(ctx, &dh->params, dh->length,
                    max_strength, priv_key))
                goto err;
        } else {
#ifdef FIPS_MODULE
            if (dh->params.q == NULL)
                goto err;
#else
            if (dh->params.q == NULL) {
                /* secret exponent length, must satisfy 2^l < (p-1)/2 */
                l = BN_num_bits(dh->params.p);
                if (dh->length >= l)
                    goto err;
                l -= 2;
                if (dh->length != 0 && dh->length < l)
                    l = dh->length;
                {
                    OSSL_FN *fn_priv = bn_acquire_ossl_fn(priv_key,
                        (l + BN_BITS2 - 1) / BN_BITS2);

                    if (fn_priv == NULL)
                        goto err;
                    if (!OSSL_FN_priv_rand(fn_priv, l, OSSL_FN_RAND_TOP_ONE,
                            OSSL_FN_RAND_BOTTOM_ANY, 0, dh->libctx))
                        goto err;
                    /*
                     * We handle just one known case where g is a quadratic
                     * non-residue: for g = 2: p % 8 == 3.  The checks are
                     * on public parameters, so they stay at the BN level.
                     */
                    if (BN_is_word(dh->params.g, DH_GENERATOR_2)
                        && !BN_is_bit_set(dh->params.p, 2)) {
                        /* clear bit 0, since it won't be a secret anyway */
                        if (!OSSL_FN_clear_bit(fn_priv, 0))
                            goto err;
                    }
                    bn_release(priv_key, (l + BN_BITS2 - 1) / BN_BITS2);
                }
            } else
#endif
            {
                /* Do a partial check for invalid p, q, g */
                if (!ossl_ffc_params_simple_validate(dh->libctx, &dh->params,
                        FFC_PARAM_TYPE_DH, NULL))
                    goto err;
                /*
                 * For FFC FIPS 186-4 keygen
                 * security strength s = 112,
                 * Max Private key size N = len(q)
                 */
                if (!ossl_ffc_generate_private_key(ctx, &dh->params,
                        BN_num_bits(dh->params.q),
                        MIN_STRENGTH,
                        priv_key))
                    goto err;
            }
        }
    }

    if (!ossl_dh_generate_public_key(ctx, dh, priv_key, pub_key))
        goto err;

    dh->pub_key = pub_key;
    dh->priv_key = priv_key;
    dh->dirty_cnt++;
    ok = 1;
err:
    if (ok != 1)
        ERR_raise(ERR_LIB_DH, ERR_R_BN_LIB);

    if (pub_key != dh->pub_key)
        BN_free(pub_key);
    if (priv_key != dh->priv_key)
        BN_free(priv_key);
    BN_CTX_free(ctx);
    return ok;
}

int ossl_dh_buf2key(DH *dh, const unsigned char *buf, size_t len)
{
    int err_reason = DH_R_BN_ERROR;
    BIGNUM *pubkey = NULL;
    const BIGNUM *p;
    int ret;

    if (len > INT_MAX || (pubkey = BN_bin2bn(buf, (int)len, NULL)) == NULL)
        goto err;
    DH_get0_pqg(dh, &p, NULL, NULL);
    if (p == NULL || BN_num_bytes(p) == 0) {
        err_reason = DH_R_NO_PARAMETERS_SET;
        goto err;
    }
    /* Prevent small subgroup attacks per RFC 8446 Section 4.2.8.1 */
    if (!ossl_dh_check_pub_key_partial(dh, pubkey, &ret)) {
        err_reason = DH_R_INVALID_PUBKEY;
        goto err;
    }
    if (DH_set0_key(dh, pubkey, NULL) != 1)
        goto err;
    return 1;
err:
    ERR_raise(ERR_LIB_DH, err_reason);
    BN_free(pubkey);
    return 0;
}

size_t ossl_dh_key2buf(const DH *dh, unsigned char **pbuf_out, size_t size,
    int alloc)
{
    const BIGNUM *pubkey;
    unsigned char *pbuf = NULL;
    const BIGNUM *p;
    int p_size;

    DH_get0_pqg(dh, &p, NULL, NULL);
    DH_get0_key(dh, &pubkey, NULL);
    if (p == NULL || pubkey == NULL
        || (p_size = BN_num_bytes(p)) == 0
        || BN_num_bytes(pubkey) == 0) {
        ERR_raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY);
        return 0;
    }
    if (pbuf_out != NULL && (alloc || *pbuf_out != NULL)) {
        if (!alloc) {
            if (size >= (size_t)p_size)
                pbuf = *pbuf_out;
            if (pbuf == NULL)
                ERR_raise(ERR_LIB_DH, DH_R_INVALID_SIZE);
        } else {
            pbuf = OPENSSL_malloc(p_size);
        }

        /* Errors raised above */
        if (pbuf == NULL)
            return 0;
        /*
         * As per Section 4.2.8.1 of RFC 8446 left pad public
         * key with zeros to the size of p
         */
        if (BN_bn2binpad(pubkey, pbuf, p_size) < 0) {
            if (alloc)
                OPENSSL_free(pbuf);
            ERR_raise(ERR_LIB_DH, DH_R_BN_ERROR);
            return 0;
        }
        *pbuf_out = pbuf;
    }
    return p_size;
}
