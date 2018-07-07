/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sm2.h"
#include "internal/sm2err.h"
#include "internal/ec_int.h" /* ec_group_do_inverse_ord() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <string.h>

static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                    const EC_KEY *key,
                                    const char *user_id,
                                    const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t *za = NULL;
    BIGNUM *e = NULL;

    if (md_size < 0) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, SM2_R_INVALID_DIGEST);
        goto done;
    }

    za = OPENSSL_zalloc(md_size);
    if (hash == NULL || za == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!sm2_compute_userid_digest(za, digest, user_id, key)) {
        /* SM2err already called */
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, za, md_size)
            || !EVP_DigestUpdate(hash, msg, msg_len)
               /* reuse za buffer to hold H(ZA || M) */
            || !EVP_DigestFinal(hash, za, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
        goto done;
    }

    e = BN_bin2bn(za, md_size, NULL);
    if (e == NULL)
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_INTERNAL_ERROR);

 done:
    OPENSSL_free(za);
    EVP_MD_CTX_free(hash);
    return e;
}

static ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e)
{
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    ECDSA_SIG *sig = NULL;
    EC_POINT *kG = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *rk = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *tmp = NULL;

    kG = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }


    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    rk = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_new();
    s = BN_new();

    if (r == NULL || s == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    for (;;) {
        if (!BN_priv_rand_range(k, order)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
                goto done;
        }

        if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
                || !EC_POINT_get_affine_coordinates_GFp(group, kG, x1, NULL,
                                                        ctx)
                || !BN_mod_add(r, e, x1, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        /* try again if r == 0 or r+k == n */
        if (BN_is_zero(r))
            continue;

        if (!BN_add(rk, r, k)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        if (BN_cmp(rk, order) == 0)
            continue;

        if (!BN_add(s, dA, BN_value_one())
                || !ec_group_do_inverse_ord(group, s, s, ctx)
                || !BN_mod_mul(tmp, dA, r, order, ctx)
                || !BN_sub(tmp, k, tmp)
                || !BN_mod_mul(s, s, tmp, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_BN_LIB);
            goto done;
        }

        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
            goto done;
        }

         /* takes ownership of r and s */
        ECDSA_SIG_set0(sig, r, s);
        break;
    }

 done:
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
    }

    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    return sig;
}

static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig,
                          const BIGNUM *e)
{
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    EC_POINT *pt = NULL;
    BIGNUM *t = NULL;
    BIGNUM *x1 = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    ctx = BN_CTX_new();
    pt = EC_POINT_new(group);
    if (ctx == NULL || pt == NULL) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: vefify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA || M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verfication pass if yes, otherwise failed
     */

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_cmp(r, BN_value_one()) < 0
            || BN_cmp(s, BN_value_one()) < 0
            || BN_cmp(order, r) <= 0
            || BN_cmp(order, s) <= 0) {
        SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!BN_mod_add(t, r, s, order, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    if (BN_is_zero(t)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx)
            || !EC_POINT_get_affine_coordinates_GFp(group, pt, x1, NULL, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_EC_LIB);
        goto done;
    }

    if (!BN_mod_add(t, e, x1, order, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    if (BN_cmp(r, t) == 0)
        ret = 1;

 done:
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    return ret;
}

ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id, const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;

    e = sm2_compute_msg_hash(digest, key, user_id, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    sig = sm2_sig_gen(key, e);

 done:
    BN_free(e);
    return sig;
}

int sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *sig,
                  const char *user_id, const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    int ret = 0;

    e = sm2_compute_msg_hash(digest, key, user_id, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    ret = sm2_sig_verify(key, sig, e);

 done:
    BN_free(e);
    return ret;
}

int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *s = NULL;
    int sigleni;
    int ret = -1;

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
       SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
       goto done;
    }

    s = sm2_sig_gen(eckey, e);

    sigleni = i2d_ECDSA_SIG(s, &sig);
    if (sigleni < 0) {
       SM2err(SM2_F_SM2_SIGN, ERR_R_INTERNAL_ERROR);
       goto done;
    }
    *siglen = (unsigned int)sigleni;

    ret = 1;

 done:
    ECDSA_SIG_free(s);
    BN_free(e);
    return ret;
}

int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s = NULL;
    BIGNUM *e = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_INVALID_ENCODING);
        goto done;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sig, der, derlen) != 0) {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_INVALID_ENCODING);
        goto done;
    }

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    ret = sm2_sig_verify(eckey, s, e);

 done:
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    return ret;
}
