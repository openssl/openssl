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

#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>

static BIGNUM *compute_msg_hash(const EVP_MD *digest,
                                const EC_KEY *key,
                                const char *user_id,
                                const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t *za = OPENSSL_zalloc(md_size);
    BIGNUM *e = NULL;

    if (za == NULL)
        goto done;

    if (hash == NULL)
        goto done;

    if (SM2_compute_userid_digest(za, digest, user_id, key) == 0)
        goto done;

    if (EVP_DigestInit(hash, digest) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, za, md_size) == 0)
        goto done;

    if (EVP_DigestUpdate(hash, msg, msg_len) == 0)
        goto done;

    /* reuse za buffer to hold H(ZA || M) */
    if (EVP_DigestFinal(hash, za, NULL) == 0)
        goto done;

    e = BN_bin2bn(za, md_size, NULL);

 done:
    OPENSSL_free(za);
    EVP_MD_CTX_free(hash);
    return e;
}

static
ECDSA_SIG *SM2_sig_gen(const EC_KEY *key, const BIGNUM *e)
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
    if (kG == NULL)
        goto done;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto done;

    BN_CTX_start(ctx);

    k = BN_CTX_get(ctx);
    rk = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (tmp == NULL)
        goto done;

    /* These values are returned and so should not be allocated out of the context */
    r = BN_new();
    s = BN_new();

    if (r == NULL || s == NULL)
        goto done;

    for (;;) {
        BN_priv_rand_range(k, order);

        if (EC_POINT_mul(group, kG, k, NULL, NULL, ctx) == 0)
            goto done;

        if (EC_POINT_get_affine_coordinates_GFp(group, kG, x1, NULL, ctx) == 0)
            goto done;

        if (BN_mod_add(r, e, x1, order, ctx) == 0)
            goto done;

        /* try again if r == 0 or r+k == n */
        if (BN_is_zero(r))
            continue;

        BN_add(rk, r, k);

        if (BN_cmp(rk, order) == 0)
            continue;

        BN_add(s, dA, BN_value_one());
        BN_mod_inverse(s, s, order, ctx);

        BN_mod_mul(tmp, dA, r, order, ctx);
        BN_sub(tmp, k, tmp);

        BN_mod_mul(s, s, tmp, order, ctx);

        sig = ECDSA_SIG_new();

        if (sig == NULL)
            goto done;

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

static
int SM2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig, const BIGNUM *e)
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
    if (ctx == NULL)
        goto done;
    pt = EC_POINT_new(group);
    if (pt == NULL)
        goto done;

    BN_CTX_start(ctx);

    t = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);

    if (x1 == NULL)
        goto done;

    /*
       B1: verify whether r' in [1,n-1], verification failed if not
       B2: vefify whether s' in [1,n-1], verification failed if not
       B3: set M'~=ZA || M'
       B4: calculate e'=Hv(M'~)
       B5: calculate t = (r' + s') modn, verification failed if t=0
       B6: calculate the point (x1', y1')=[s']G + [t]PA
       B7: calculate R=(e'+x1') modn, verfication pass if yes, otherwise failed
     */

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_cmp(r, BN_value_one()) < 0)
        goto done;
    if (BN_cmp(s, BN_value_one()) < 0)
        goto done;

    if (BN_cmp(order, r) <= 0)
        goto done;
    if (BN_cmp(order, s) <= 0)
        goto done;

    if (BN_mod_add(t, r, s, order, ctx) == 0)
        goto done;

    if (BN_is_zero(t) == 1)
        goto done;

    if (EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx) == 0)
        goto done;

    if (EC_POINT_get_affine_coordinates_GFp(group, pt, x1, NULL, ctx) == 0)
        goto done;

    if (BN_mod_add(t, e, x1, order, ctx) == 0)
        goto done;

    if (BN_cmp(r, t) == 0)
        ret = 1;

 done:
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    return ret;
}

ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const char *user_id, const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;

    e = compute_msg_hash(digest, key, user_id, msg, msg_len);
    if (e == NULL)
        goto done;

    sig = SM2_sig_gen(key, e);

 done:
    BN_free(e);
    return sig;
}

int SM2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *sig,
                  const char *user_id, const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    int ret = -1;

    e = compute_msg_hash(digest, key, user_id, msg, msg_len);
    if (e == NULL)
        goto done;

    ret = SM2_sig_verify(key, sig, e);

 done:
    BN_free(e);
    return ret;
}

int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *s = NULL;
    int ret = -1;

    if (type != NID_sm3)
        goto done;

    if (dgstlen != 32)          /* expected length of SM3 hash */
        goto done;

    e = BN_bin2bn(dgst, dgstlen, NULL);

    s = SM2_sig_gen(eckey, e);

    *siglen = i2d_ECDSA_SIG(s, &sig);

    ECDSA_SIG_free(s);

    ret = 0;

 done:
    ECDSA_SIG_free(s);
    BN_free(e);
    return ret;
}

int SM2_verify(int type, const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s = NULL;
    BIGNUM *e = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    if (type != NID_sm3)
        goto done;

    s = ECDSA_SIG_new();
    if (s == NULL)
        goto done;
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto done;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sig, der, derlen) != 0)
        goto done;

    e = BN_bin2bn(dgst, dgstlen, NULL);

    ret = SM2_sig_verify(eckey, s, e);

 done:
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    return ret;
}
