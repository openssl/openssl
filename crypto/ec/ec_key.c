/*
 * Copyright 2002-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <string.h>
#include "ec_local.h"
#include "internal/refcount.h"
#include <openssl/err.h>
#include <openssl/engine.h>

#ifndef FIPS_MODE
EC_KEY *EC_KEY_new(void)
{
    return ec_key_new_method_int(NULL, NULL);
}
#endif

EC_KEY *EC_KEY_new_ex(OPENSSL_CTX *ctx)
{
    return ec_key_new_method_int(ctx, NULL);
}

EC_KEY *EC_KEY_new_by_curve_name_ex(OPENSSL_CTX *ctx, int nid)
{
    EC_KEY *ret = EC_KEY_new_ex(ctx);
    if (ret == NULL)
        return NULL;
    ret->group = EC_GROUP_new_by_curve_name_ex(ctx, nid);
    if (ret->group == NULL) {
        EC_KEY_free(ret);
        return NULL;
    }
    if (ret->meth->set_group != NULL
        && ret->meth->set_group(ret, ret->group) == 0) {
        EC_KEY_free(ret);
        return NULL;
    }
    return ret;
}

#ifndef FIPS_MODE
EC_KEY *EC_KEY_new_by_curve_name(int nid)
{
    return EC_KEY_new_by_curve_name_ex(NULL, nid);
}
#endif

void EC_KEY_free(EC_KEY *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("EC_KEY", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
    ENGINE_finish(r->engine);
#endif

    if (r->group && r->group->meth->keyfinish)
        r->group->meth->keyfinish(r);

#ifndef FIPS_MODE
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EC_KEY, r, &r->ex_data);
#endif
    CRYPTO_THREAD_lock_free(r->lock);
    EC_GROUP_free(r->group);
    EC_POINT_free(r->pub_key);
    BN_clear_free(r->priv_key);

    OPENSSL_clear_free((void *)r, sizeof(EC_KEY));
}

EC_KEY *EC_KEY_copy(EC_KEY *dest, const EC_KEY *src)
{
    if (dest == NULL || src == NULL) {
        ECerr(EC_F_EC_KEY_COPY, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (src->meth != dest->meth) {
        if (dest->meth->finish != NULL)
            dest->meth->finish(dest);
        if (dest->group && dest->group->meth->keyfinish)
            dest->group->meth->keyfinish(dest);
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
        if (ENGINE_finish(dest->engine) == 0)
            return 0;
        dest->engine = NULL;
#endif
    }
    dest->libctx = src->libctx;
    /* copy the parameters */
    if (src->group != NULL) {
        const EC_METHOD *meth = EC_GROUP_method_of(src->group);
        /* clear the old group */
        EC_GROUP_free(dest->group);
        dest->group = EC_GROUP_new_ex(src->libctx, meth);
        if (dest->group == NULL)
            return NULL;
        if (!EC_GROUP_copy(dest->group, src->group))
            return NULL;

        /*  copy the public key */
        if (src->pub_key != NULL) {
            EC_POINT_free(dest->pub_key);
            dest->pub_key = EC_POINT_new(src->group);
            if (dest->pub_key == NULL)
                return NULL;
            if (!EC_POINT_copy(dest->pub_key, src->pub_key))
                return NULL;
        }
        /* copy the private key */
        if (src->priv_key != NULL) {
            if (dest->priv_key == NULL) {
                dest->priv_key = BN_new();
                if (dest->priv_key == NULL)
                    return NULL;
            }
            if (!BN_copy(dest->priv_key, src->priv_key))
                return NULL;
            if (src->group->meth->keycopy
                && src->group->meth->keycopy(dest, src) == 0)
                return NULL;
        }
    }


    /* copy the rest */
    dest->enc_flag = src->enc_flag;
    dest->conv_form = src->conv_form;
    dest->version = src->version;
    dest->flags = src->flags;
#ifndef FIPS_MODE
    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EC_KEY,
                            &dest->ex_data, &src->ex_data))
        return NULL;
#endif

    if (src->meth != dest->meth) {
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODE)
        if (src->engine != NULL && ENGINE_init(src->engine) == 0)
            return NULL;
        dest->engine = src->engine;
#endif
        dest->meth = src->meth;
    }

    if (src->meth->copy != NULL && src->meth->copy(dest, src) == 0)
        return NULL;

    return dest;
}

EC_KEY *EC_KEY_dup(const EC_KEY *ec_key)
{
    EC_KEY *ret = ec_key_new_method_int(ec_key->libctx, ec_key->engine);

    if (ret == NULL)
        return NULL;

    if (EC_KEY_copy(ret, ec_key) == NULL) {
        EC_KEY_free(ret);
        return NULL;
    }
    return ret;
}

int EC_KEY_up_ref(EC_KEY *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("EC_KEY", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

ENGINE *EC_KEY_get0_engine(const EC_KEY *eckey)
{
    return eckey->engine;
}

int EC_KEY_generate_key(EC_KEY *eckey)
{
    if (eckey == NULL || eckey->group == NULL) {
        ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (eckey->meth->keygen != NULL)
        return eckey->meth->keygen(eckey);
    ECerr(EC_F_EC_KEY_GENERATE_KEY, EC_R_OPERATION_NOT_SUPPORTED);
    return 0;
}

int ossl_ec_key_gen(EC_KEY *eckey)
{
    return eckey->group->meth->keygen(eckey);
}

/*
 * ECC Key generation.
 * See SP800-56AR3 5.6.1.2.2 "Key Pair Generation by Testing Candidates"
 *
 * Params:
 *     eckey An EC key object that contains domain params. The generated keypair
 *           is stored in this object.
 * Returns 1 if the keypair was generated or 0 otherwise.
 */
int ec_key_simple_generate_key(EC_KEY *eckey)
{
    int ok = 0;
    BIGNUM *priv_key = NULL;
    const BIGNUM *order = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = eckey->group;
    BN_CTX *ctx = BN_CTX_secure_new_ex(eckey->libctx);

    if (ctx == NULL)
        goto err;

    if (eckey->priv_key == NULL) {
        priv_key = BN_secure_new();
        if (priv_key == NULL)
            goto err;
    } else
        priv_key = eckey->priv_key;

    /*
     * Steps (1-2): Check domain parameters and security strength.
     * These steps must be done by the user. This would need to be
     * stated in the security policy.
     */

    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;

    /*
     * Steps (3-7): priv_key = DRBG_RAND(order_n_bits) (range [1, n-1]).
     * Although this is slightly different from the standard, it is effectively
     * equivalent as it gives an unbiased result ranging from 1..n-1. It is also
     * faster as the standard needs to retry more often. Also doing
     * 1 + rand[0..n-2] would effect the way that tests feed dummy entropy into
     * rand so the simpler backward compatible method has been used here.
     */
    do
        if (!BN_priv_rand_range_ex(priv_key, order, ctx))
            goto err;
    while (BN_is_zero(priv_key)) ;

    if (eckey->pub_key == NULL) {
        pub_key = EC_POINT_new(group);
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = eckey->pub_key;

    /* Step (8) : pub_key = priv_key * G (where G is a point on the curve) */
    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    eckey->priv_key = priv_key;
    eckey->pub_key = pub_key;
    priv_key = NULL;
    pub_key = NULL;

    ok = 1;

err:
    /* Step (9): If there is an error return an invalid keypair. */
    if (!ok) {
        BN_clear(eckey->priv_key);
        if (eckey->pub_key != NULL)
            EC_POINT_set_to_infinity(group, eckey->pub_key);
    }

    EC_POINT_free(pub_key);
    BN_clear_free(priv_key);
    BN_CTX_free(ctx);
    return ok;
}

int ec_key_simple_generate_public_key(EC_KEY *eckey)
{
    /*
     * See SP800-56AR3 5.6.1.2.2: Step (8)
     * pub_key = priv_key * G (where G is a point on the curve)
     */
    return EC_POINT_mul(eckey->group, eckey->pub_key, eckey->priv_key, NULL,
                        NULL, NULL);
}

int EC_KEY_check_key(const EC_KEY *eckey)
{
    if (eckey == NULL || eckey->group == NULL || eckey->pub_key == NULL) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (eckey->group->meth->keycheck == NULL) {
        ECerr(EC_F_EC_KEY_CHECK_KEY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    return eckey->group->meth->keycheck(eckey);
}

/*
 * Check the range of the EC public key.
 * See SP800-56A R3 Section 5.6.2.3.3 (Part 2)
 * i.e.
 *  - If q = odd prime p: Verify that xQ and yQ are integers in the
 *    interval[0, p - 1], OR
 *  - If q = 2m: Verify that xQ and yQ are bit strings of length m bits.
 * Returns 1 if the public key has a valid range, otherwise it returns 0.
 */
static int ec_key_public_range_check(BN_CTX *ctx, const EC_KEY *key)
{
    int ret = 0;
    BIGNUM *x, *y;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (y == NULL)
        goto err;

    if (!EC_POINT_get_affine_coordinates(key->group, key->pub_key, x, y, ctx))
        goto err;

    if (EC_METHOD_get_field_type(key->group->meth) == NID_X9_62_prime_field) {
        if (BN_is_negative(x)
            || BN_cmp(x, key->group->field) >= 0
            || BN_is_negative(y)
            || BN_cmp(y, key->group->field) >= 0) {
            goto err;
        }
    } else {
        int m = EC_GROUP_get_degree(key->group);
        if (BN_num_bits(x) > m || BN_num_bits(y) > m) {
            goto err;
        }
    }
    ret = 1;
err:
    BN_CTX_end(ctx);
    return ret;
}

/*
 * ECC Key validation as specified in SP800-56A R3.
 *    Section 5.6.2.3.3 ECC Full Public-Key Validation
 *    Section 5.6.2.1.2 Owner Assurance of Private-Key Validity
 *    Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency
 * NOTES:
 *    Before calling this method in fips mode, there should be an assurance that
 *    an approved elliptic-curve group is used.
 * Returns 1 if the key is valid, otherwise it returns 0.
 */
int ec_key_simple_check_key(const EC_KEY *eckey)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    const BIGNUM *order = NULL;
    EC_POINT *point = NULL;

    if (eckey == NULL || eckey->group == NULL || eckey->pub_key == NULL) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* 5.6.2.3.3 (Step 1): Q != infinity */
    if (EC_POINT_is_at_infinity(eckey->group, eckey->pub_key)) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_POINT_AT_INFINITY);
        goto err;
    }

    if ((ctx = BN_CTX_new_ex(eckey->libctx)) == NULL)
        goto err;

    if ((point = EC_POINT_new(eckey->group)) == NULL)
        goto err;

    /* 5.6.2.3.3 (Step 2) Test if the public key is in range */
    if (!ec_key_public_range_check(ctx, eckey)) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }

    /* 5.6.2.3.3 (Step 3) is the pub_key on the elliptic curve */
    if (EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx) <= 0) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_POINT_IS_NOT_ON_CURVE);
        goto err;
    }

    order = eckey->group->order;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }
    /* 5.6.2.3.3 (Step 4) : pub_key * order is the point at infinity. */
    if (!EC_POINT_mul(eckey->group, point, NULL, eckey->pub_key, order, ctx)) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_is_at_infinity(eckey->group, point)) {
        ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_WRONG_ORDER);
        goto err;
    }

    if (eckey->priv_key != NULL) {
        /*
         * 5.6.2.1.2 Owner Assurance of Private-Key Validity
         * The private key is in the range [1, order-1]
         */
        if (BN_cmp(eckey->priv_key, BN_value_one()) < 0
                || BN_cmp(eckey->priv_key, order) >= 0) {
            ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_WRONG_ORDER);
            goto err;
        }
        /*
         * Section 5.6.2.1.4 Owner Assurance of Pair-wise Consistency (b)
         * Check if generator * priv_key = pub_key
         */
        if (!EC_POINT_mul(eckey->group, point, eckey->priv_key,
                          NULL, NULL, ctx)) {
            ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, ERR_R_EC_LIB);
            goto err;
        }
        if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, ctx) != 0) {
            ECerr(EC_F_EC_KEY_SIMPLE_CHECK_KEY, EC_R_INVALID_PRIVATE_KEY);
            goto err;
        }
    }
    ok = 1;
 err:
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ok;
}

int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                             BIGNUM *y)
{
    BN_CTX *ctx = NULL;
    BIGNUM *tx, *ty;
    EC_POINT *point = NULL;
    int ok = 0;

    if (key == NULL || key->group == NULL || x == NULL || y == NULL) {
        ECerr(EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES,
              ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    ctx = BN_CTX_new_ex(key->libctx);
    if (ctx == NULL)
        return 0;

    BN_CTX_start(ctx);
    point = EC_POINT_new(key->group);

    if (point == NULL)
        goto err;

    tx = BN_CTX_get(ctx);
    ty = BN_CTX_get(ctx);
    if (ty == NULL)
        goto err;

    if (!EC_POINT_set_affine_coordinates(key->group, point, x, y, ctx))
        goto err;
    if (!EC_POINT_get_affine_coordinates(key->group, point, tx, ty, ctx))
        goto err;

    /*
     * Check if retrieved coordinates match originals. The range check is done
     * inside EC_KEY_check_key().
     */
    if (BN_cmp(x, tx) || BN_cmp(y, ty)) {
        ECerr(EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES,
              EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }

    if (!EC_KEY_set_public_key(key, point))
        goto err;

    if (EC_KEY_check_key(key) == 0)
        goto err;

    ok = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ok;

}

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key)
{
    return key->group;
}

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group)
{
    if (key->meth->set_group != NULL && key->meth->set_group(key, group) == 0)
        return 0;
    EC_GROUP_free(key->group);
    key->group = EC_GROUP_dup(group);
    return (key->group == NULL) ? 0 : 1;
}

const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key)
{
    return key->priv_key;
}

int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key)
{
    if (key->group == NULL || key->group->meth == NULL)
        return 0;
    if (key->group->meth->set_private != NULL
        && key->group->meth->set_private(key, priv_key) == 0)
        return 0;
    if (key->meth->set_private != NULL
        && key->meth->set_private(key, priv_key) == 0)
        return 0;
    BN_clear_free(key->priv_key);
    key->priv_key = BN_dup(priv_key);
    return (key->priv_key == NULL) ? 0 : 1;
}

const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key)
{
    return key->pub_key;
}

int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub_key)
{
    if (key->meth->set_public != NULL
        && key->meth->set_public(key, pub_key) == 0)
        return 0;
    EC_POINT_free(key->pub_key);
    key->pub_key = EC_POINT_dup(pub_key, key->group);
    return (key->pub_key == NULL) ? 0 : 1;
}

unsigned int EC_KEY_get_enc_flags(const EC_KEY *key)
{
    return key->enc_flag;
}

void EC_KEY_set_enc_flags(EC_KEY *key, unsigned int flags)
{
    key->enc_flag = flags;
}

point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key)
{
    return key->conv_form;
}

void EC_KEY_set_conv_form(EC_KEY *key, point_conversion_form_t cform)
{
    key->conv_form = cform;
    if (key->group != NULL)
        EC_GROUP_set_point_conversion_form(key->group, cform);
}

void EC_KEY_set_asn1_flag(EC_KEY *key, int flag)
{
    if (key->group != NULL)
        EC_GROUP_set_asn1_flag(key->group, flag);
}

int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx)
{
    if (key->group == NULL)
        return 0;
    return EC_GROUP_precompute_mult(key->group, ctx);
}

int EC_KEY_get_flags(const EC_KEY *key)
{
    return key->flags;
}

void EC_KEY_set_flags(EC_KEY *key, int flags)
{
    key->flags |= flags;
}

void EC_KEY_clear_flags(EC_KEY *key, int flags)
{
    key->flags &= ~flags;
}

size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form,
                        unsigned char **pbuf, BN_CTX *ctx)
{
    if (key == NULL || key->pub_key == NULL || key->group == NULL)
        return 0;
    return EC_POINT_point2buf(key->group, key->pub_key, form, pbuf, ctx);
}

int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len,
                   BN_CTX *ctx)
{
    if (key == NULL || key->group == NULL)
        return 0;
    if (key->pub_key == NULL)
        key->pub_key = EC_POINT_new(key->group);
    if (key->pub_key == NULL)
        return 0;
    if (EC_POINT_oct2point(key->group, key->pub_key, buf, len, ctx) == 0)
        return 0;
    /*
     * Save the point conversion form.
     * For non-custom curves the first octet of the buffer (excluding
     * the last significant bit) contains the point conversion form.
     * EC_POINT_oct2point() has already performed sanity checking of
     * the buffer so we know it is valid.
     */
    if ((key->group->meth->flags & EC_FLAGS_CUSTOM_CURVE) == 0)
        key->conv_form = (point_conversion_form_t)(buf[0] & ~0x01);
    return 1;
}

size_t EC_KEY_priv2oct(const EC_KEY *eckey,
                       unsigned char *buf, size_t len)
{
    if (eckey->group == NULL || eckey->group->meth == NULL)
        return 0;
    if (eckey->group->meth->priv2oct == NULL) {
        ECerr(EC_F_EC_KEY_PRIV2OCT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    return eckey->group->meth->priv2oct(eckey, buf, len);
}

size_t ec_key_simple_priv2oct(const EC_KEY *eckey,
                              unsigned char *buf, size_t len)
{
    size_t buf_len;

    buf_len = (EC_GROUP_order_bits(eckey->group) + 7) / 8;
    if (eckey->priv_key == NULL)
        return 0;
    if (buf == NULL)
        return buf_len;
    else if (len < buf_len)
        return 0;

    /* Octetstring may need leading zeros if BN is to short */

    if (BN_bn2binpad(eckey->priv_key, buf, buf_len) == -1) {
        ECerr(EC_F_EC_KEY_SIMPLE_PRIV2OCT, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    return buf_len;
}

int EC_KEY_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len)
{
    if (eckey->group == NULL || eckey->group->meth == NULL)
        return 0;
    if (eckey->group->meth->oct2priv == NULL) {
        ECerr(EC_F_EC_KEY_OCT2PRIV, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return eckey->group->meth->oct2priv(eckey, buf, len);
}

int ec_key_simple_oct2priv(EC_KEY *eckey, const unsigned char *buf, size_t len)
{
    if (eckey->priv_key == NULL)
        eckey->priv_key = BN_secure_new();
    if (eckey->priv_key == NULL) {
        ECerr(EC_F_EC_KEY_SIMPLE_OCT2PRIV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    eckey->priv_key = BN_bin2bn(buf, len, eckey->priv_key);
    if (eckey->priv_key == NULL) {
        ECerr(EC_F_EC_KEY_SIMPLE_OCT2PRIV, ERR_R_BN_LIB);
        return 0;
    }
    return 1;
}

size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf)
{
    size_t len;
    unsigned char *buf;

    len = EC_KEY_priv2oct(eckey, NULL, 0);
    if (len == 0)
        return 0;
    if ((buf = OPENSSL_malloc(len)) == NULL) {
        ECerr(EC_F_EC_KEY_PRIV2BUF, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    len = EC_KEY_priv2oct(eckey, buf, len);
    if (len == 0) {
        OPENSSL_free(buf);
        return 0;
    }
    *pbuf = buf;
    return len;
}

int EC_KEY_can_sign(const EC_KEY *eckey)
{
    if (eckey->group == NULL || eckey->group->meth == NULL
        || (eckey->group->meth->flags & EC_FLAGS_NO_SIGN))
        return 0;
    return 1;
}
