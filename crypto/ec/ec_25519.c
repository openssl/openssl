/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ec_lcl.h"

/* Length of Curve 25519 keys */
#define EC_X25519_KEYLEN    32
/* Group degree and order bits */
#define EC_X25519_BITS      253

/* Copy Curve25519 public key buffer, allocating is necessary */
static int x25519_init_public(EC_POINT *pub, const void *src)
{
    if (pub->custom_data == NULL) {
        pub->custom_data = OPENSSL_malloc(EC_X25519_KEYLEN);
        if (pub->custom_data == NULL)
            return 0;
    }
    if (src != NULL)
        memcpy(pub->custom_data, src, EC_X25519_KEYLEN);
    return 1;
}

/* Copy Curve25519 private key buffer, allocating is necessary */
static int x25519_init_private(EC_KEY *dst, const void *src)
{
    if (dst->custom_data == NULL) {
        dst->custom_data = OPENSSL_secure_malloc(EC_X25519_KEYLEN);
        if (dst->custom_data == NULL)
            return 0;
    }
    if (src != NULL)
        memcpy(dst->custom_data, src, EC_X25519_KEYLEN);
    return 1;
}

static int x25519_group_init(EC_GROUP *grp)
{
    return 1;
}

static int x25519_group_copy(EC_GROUP *dst, const EC_GROUP *src)
{
    return 1;
}

static int x25519_group_get_degree(const EC_GROUP *src)
{
    return EC_X25519_BITS;
}

static int x25519_group_order_bits(const EC_GROUP *src)
{
    return EC_X25519_BITS;
}

static int x25519_set_private(EC_KEY *eckey, const BIGNUM *priv_key)
{
    if (BN_num_bytes(priv_key) > EC_X25519_KEYLEN)
        return 0;
    if (x25519_init_private(eckey, NULL))
        return 0;
    /* Convert BIGNUM form private key to internal format */
    if (BN_bn2lebinpad(priv_key, eckey->custom_data, EC_X25519_KEYLEN)
        != EC_X25519_KEYLEN)
        return 0;
    return 1;
}

static int x25519_keycheck(const EC_KEY *eckey)
{
    const char *pubkey;
    if (eckey->pub_key == NULL)
        return 0;
    pubkey = eckey->pub_key->custom_data;
    if (pubkey == NULL)
        return 0;
    if (eckey->custom_data != NULL) {
        uint8_t tmp[EC_X25519_KEYLEN];
        /* Check eckey->priv_key exists and matches eckey->custom_data */
        if (eckey->priv_key == NULL)
            return 0;
        if (BN_bn2lebinpad(eckey->priv_key, tmp, EC_X25519_KEYLEN)
            != EC_X25519_KEYLEN
            || CRYPTO_memcmp(tmp, eckey->custom_data,
                             EC_X25519_KEYLEN) != 0) {
            OPENSSL_cleanse(tmp, EC_X25519_KEYLEN);
            return 0;
        }
        X25519_public_from_private(tmp, eckey->custom_data);
        if (CRYPTO_memcmp(pubkey, tmp, EC_X25519_KEYLEN) == 0)
            return 1;
        return 0;
    } else {
        return 1;
    }
}

static int x25519_keygenpub(EC_KEY *eckey)
{
    X25519_public_from_private(eckey->pub_key->custom_data,
                               eckey->custom_data);
    return 1;
}

static int x25519_keygen(EC_KEY *eckey)
{
    unsigned char *key;
    if (x25519_init_private(eckey, NULL) == 0)
        return 0;
    key = eckey->custom_data;
    if (RAND_bytes(key, EC_X25519_KEYLEN) <= 0)
        return 0;
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    /*
     * Although the private key is kept as an array in eckey->custom_data
     * Set eckey->priv_key too so existing code which uses
     * EC_KEY_get0_private_key() still works.
     */
    if (eckey->priv_key == NULL)
        eckey->priv_key = BN_secure_new();
    if (eckey->priv_key == NULL)
        return 0;
    if (BN_lebin2bn(eckey->custom_data, EC_X25519_KEYLEN, eckey->priv_key) ==
        NULL)
        return 0;
    if (eckey->pub_key == NULL)
        eckey->pub_key = EC_POINT_new(eckey->group);
    if (eckey->pub_key == NULL)
        return 0;
    return x25519_keygenpub(eckey);
}

static void x25519_keyfinish(EC_KEY *eckey)
{
    OPENSSL_secure_free(eckey->custom_data);
    eckey->custom_data = NULL;
}

static int x25519_keycopy(EC_KEY *dest, const EC_KEY *src)
{
    if (src->custom_data == NULL)
        return 0;
    return x25519_init_private(dest, src->custom_data);
}

static int x25519_oct2priv(EC_KEY *eckey, unsigned char *buf, size_t len)
{
    if (len != EC_X25519_KEYLEN)
        return 0;
    if (x25519_init_private(eckey, buf) == 0)
        return 0;
    /*
     * Although the private key is kept as an array in eckey->custom_data
     * Set eckey->priv_key too so existing code which uses
     * EC_KEY_get0_private_key() still works.
     */
    if (eckey->priv_key == NULL)
        eckey->priv_key = BN_secure_new();
    if (eckey->priv_key == NULL)
        return 0;
    if (BN_lebin2bn(buf, EC_X25519_KEYLEN, eckey->priv_key) == NULL)
        return 0;
    return 1;
}

static size_t x25519_priv2oct(const EC_KEY *eckey,
                              unsigned char *buf, size_t len)
{
    size_t keylen = EC_X25519_KEYLEN;
    if (eckey->custom_data == NULL)
        return 0;
    if (buf != NULL) {
        if (len < keylen)
            return 0;
        memcpy(buf, eckey->custom_data, keylen);
    }
    return keylen;
}

static int x25519_point_init(EC_POINT *pt)
{
    return x25519_init_public(pt, NULL);
}

static void x25519_point_finish(EC_POINT *pt)
{
    OPENSSL_free(pt->custom_data);
    pt->custom_data = NULL;
}

static void x25519_point_clear_finish(EC_POINT *pt)
{
    OPENSSL_clear_free(pt->custom_data, EC_X25519_KEYLEN);
    pt->custom_data = NULL;
}

static int x25519_point_copy(EC_POINT *dst, const EC_POINT *src)
{
    memcpy(dst->custom_data, src->custom_data, EC_X25519_KEYLEN);
    return 1;
}

static size_t x25519_point2oct(const EC_GROUP *grp, const EC_POINT *pt,
                               point_conversion_form_t form,
                               unsigned char *buf, size_t len, BN_CTX *ctx)
{
    if (buf != NULL) {
        if (len < EC_X25519_KEYLEN)
            return 0;
        memcpy(buf, pt->custom_data, EC_X25519_KEYLEN);
    }
    return EC_X25519_KEYLEN;
}

static int x25519_oct2point(const EC_GROUP *grp, EC_POINT *pt,
                            const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    unsigned char *pubkey = pt->custom_data;
    if (len != EC_X25519_KEYLEN)
        return 0;
    memcpy(pubkey, buf, EC_X25519_KEYLEN);
    /* Mask off MSB */
    pubkey[EC_X25519_KEYLEN - 1] &= 0x7F;
    return 1;
}

static int x25519_point_cmp(const EC_GROUP *group, const EC_POINT *a,
                            const EC_POINT *b, BN_CTX *ctx)
{
    /* Shouldn't happen as initialised to non-zero */
    if (a->custom_data == NULL || b->custom_data == NULL)
        return -1;

    if (CRYPTO_memcmp(a->custom_data, b->custom_data, EC_X25519_KEYLEN) == 0)
        return 0;

    return 1;
}

static int x25519_compute_key(unsigned char **psec, size_t *pseclen,
                              const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    unsigned char *key;
    int ret = -1;
    if (ecdh->custom_data == NULL)
        return -1;
    key = OPENSSL_malloc(EC_X25519_KEYLEN);
    if (key == NULL)
        return 0;
    if (X25519(key, ecdh->custom_data, pub_key->custom_data) == 0)
        goto err;
    *psec = key;
    *pseclen = EC_X25519_KEYLEN;
    return 1;

 err:
    OPENSSL_clear_free(key, EC_X25519_KEYLEN);
    return ret;
}

const EC_METHOD *ec_x25519_meth(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_CUSTOM_CURVE | EC_FLAGS_NO_SIGN,
        NID_undef,
        x25519_group_init,      /* group_init */
        0,                      /* group_finish */
        0,                      /* group_clear_finish */
        x25519_group_copy,      /* group_copy */
        0,                      /* group_set_curve */
        0,                      /* group_get_curve */
        x25519_group_get_degree,
        x25519_group_order_bits,
        0,                      /* group_check_discriminant */
        x25519_point_init,
        x25519_point_finish,
        x25519_point_clear_finish,
        x25519_point_copy,
        0,                      /* point_set_to_infinity */
        0,                      /* set_Jprojective_coordinates_GFp */
        0,                      /* get_Jprojective_coordinates_GFp */
        0,                      /* point_set_affine_coordinates */
        0,                      /* point_get_affine_coordinates */
        0,                      /* point_set_compressed_coordinates */
        x25519_point2oct,
        x25519_oct2point,
        0,                      /* simple_add */
        0,                      /* simple_dbl */
        0,                      /* simple_invert */
        0,                      /* simple_is_at_infinity */
        0,                      /* simple_is_on_curve */
        x25519_point_cmp,
        0,                      /* simple_make_affine */
        0,                      /* simple_points_make_affine */
        0,                      /* points_mul */
        0,                      /* precompute_mult */
        0,                      /* have_precompute_mult */
        0,                      /* field_mul */
        0,                      /* field_sqr */
        0,                      /* field_div */
        0,                      /* field_encode */
        0,                      /* field_decode */
        0,                      /* field_set_to_one */
        x25519_priv2oct,
        x25519_oct2priv,
        x25519_set_private,
        x25519_keygen,
        x25519_keycheck,
        x25519_keygenpub,
        x25519_keycopy,
        x25519_keyfinish,
        x25519_compute_key
    };

    return &ret;
}
