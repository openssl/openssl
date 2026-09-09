/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include <openssl/rand.h>
#include "rsa_local.h"

int RSA_bits(const RSA *r)
{
    return BN_num_bits(r->n);
}

int RSA_size(const RSA *r)
{
    return BN_num_bytes(r->n);
}

int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
    return rsa->meth->rsa_pub_enc(flen, from, to, rsa, padding);
}

int RSA_private_encrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding)
{
    return rsa->meth->rsa_priv_enc(flen, from, to, rsa, padding);
}

int RSA_private_decrypt(int flen, const unsigned char *from,
    unsigned char *to, RSA *rsa, int padding)
{
    return rsa->meth->rsa_priv_dec(flen, from, to, rsa, padding);
}

int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding)
{
    return rsa->meth->rsa_pub_dec(flen, from, to, rsa, padding);
}

int RSA_flags(const RSA *r)
{
    return r == NULL ? 0 : r->meth->flags;
}

void RSA_blinding_off(RSA *rsa)
{
    rsa->flags &= ~RSA_FLAG_BLINDING;
    rsa->flags |= RSA_FLAG_NO_BLINDING;
}

int RSA_blinding_on(RSA *rsa, BN_CTX *ctx)
{

    rsa->flags |= RSA_FLAG_BLINDING;
    rsa->flags &= ~RSA_FLAG_NO_BLINDING;
    return 1;
}

static BIGNUM *rsa_get_public_exp(const BIGNUM *d, const BIGNUM *p,
    const BIGNUM *q)
{
    /* e = d^-1 mod (p-1)(q-1), computed on OSSL_FN views */
    BIGNUM *ret = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *r0 = NULL, *r1 = NULL, *r2 = NULL, *fn_e = NULL;
    const OSSL_FN *fn_d, *fn_p, *fn_q;
    size_t pl, ql, nl, fn_size;
    int e_bits;

    if (d == NULL || p == NULL || q == NULL)
        return NULL;

    fn_d = bn_get_ossl_fn(d);
    fn_p = bn_get_ossl_fn(p);
    fn_q = bn_get_ossl_fn(q);
    if (fn_d == NULL || fn_p == NULL || fn_q == NULL)
        return NULL;
    pl = ossl_fn_get_dsize((OSSL_FN *)fn_p);
    ql = ossl_fn_get_dsize((OSSL_FN *)fn_q);
    nl = pl + ql;

    r0 = OSSL_FN_secure_new_limbs(nl);
    r1 = OSSL_FN_secure_new_limbs(pl);
    r2 = OSSL_FN_secure_new_limbs(ql);
    if (r0 == NULL || r1 == NULL || r2 == NULL)
        goto err;

    if (!OSSL_FN_copy(r1, fn_p) || !OSSL_FN_sub_word(r1, 1)
        || !OSSL_FN_copy(r2, fn_q) || !OSSL_FN_sub_word(r2, 1))
        goto err;

    /* The mul and the mod_inverse run sequentially in one arena. */
    fn_size = ossl_fn_ctx_max_size(OSSL_FN_mul_ctx_size(r0, r1, r2),
        OSSL_FN_mod_inverse_ctx_size(r0, fn_d, r0));
    if (fn_size == 0)
        goto err;
    fn_ctx = OSSL_FN_CTX_secure_new_size(NULL, fn_size);
    if (fn_ctx == NULL)
        goto err;

    if (!OSSL_FN_mul(r0, r1, r2, fn_ctx))
        goto err;

    ret = BN_new();
    if (ret == NULL)
        goto err;
    fn_e = bn_acquire_ossl_fn(ret, (int)nl);
    if (fn_e == NULL) {
        BN_free(ret);
        ret = NULL;
        goto err;
    }
    if (!OSSL_FN_mod_inverse(fn_e, fn_d, r0, fn_ctx)) {
        BN_free(ret);
        ret = NULL;
        goto err;
    }
    e_bits = (int)OSSL_FN_num_bits(fn_e);
    bn_release(ret, e_bits > 0 ? (e_bits + BN_BITS2 - 1) / BN_BITS2 : 1);

err:
    OSSL_FN_CTX_free(fn_ctx);
    OSSL_FN_clear_free(r0);
    OSSL_FN_clear_free(r1);
    OSSL_FN_clear_free(r2);
    return ret;
}

BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *in_ctx)
{
    BIGNUM *e;
    BN_CTX *ctx;
    BN_BLINDING *ret = NULL;

    if (in_ctx == NULL) {
        if ((ctx = BN_CTX_new_ex(rsa->libctx)) == NULL)
            return 0;
    } else {
        ctx = in_ctx;
    }

    BN_CTX_start(ctx);
    e = BN_CTX_get(ctx);
    if (e == NULL) {
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }

    if (rsa->e == NULL) {
        e = rsa_get_public_exp(rsa->d, rsa->p, rsa->q);
        if (e == NULL) {
            ERR_raise(ERR_LIB_RSA, RSA_R_NO_PUBLIC_EXPONENT);
            goto err;
        }
    } else {
        e = rsa->e;
    }

    {
        BIGNUM *n = BN_new();

        if (n == NULL) {
            ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
            goto err;
        }
        BN_with_flags(n, rsa->n, BN_FLG_CONSTTIME);

        ret = BN_BLINDING_create_param(NULL, e, n, ctx, rsa->meth->bn_mod_exp,
            rsa->_method_mod_n);
        /* We MUST free n before any further use of rsa->n */
        BN_free(n);
    }
    if (ret == NULL) {
        ERR_raise(ERR_LIB_RSA, ERR_R_BN_LIB);
        goto err;
    }

err:
    BN_CTX_end(ctx);
    if (ctx != in_ctx)
        BN_CTX_free(ctx);
    if (e != rsa->e)
        BN_free(e);

    return ret;
}
