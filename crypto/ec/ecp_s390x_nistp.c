/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * EC_METHOD low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "ec_local.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "arch/s390x_arch.h"

/* Size of parameter blocks */
#define S390X_SIZE_PARAM 4096

/* Size of fields in parameter blocks */
#define S390X_SIZE_P256 32
#define S390X_SIZE_P384 48
#define S390X_SIZE_P521 80

/* Offsets of fields in PCC parameter blocks */
#define S390X_OFF_RES_X(n) (0 * n)
#define S390X_OFF_RES_Y(n) (1 * n)
#define S390X_OFF_SRC_X(n) (2 * n)
#define S390X_OFF_SRC_Y(n) (3 * n)
#define S390X_OFF_SCALAR(n) (4 * n)

/* Offsets of fields in KDSA parameter blocks */
#define S390X_OFF_R(n) (0 * n)
#define S390X_OFF_S(n) (1 * n)
#define S390X_OFF_H(n) (2 * n)
#define S390X_OFF_K(n) (3 * n)
#define S390X_OFF_X(n) (3 * n)
#define S390X_OFF_RN(n) (4 * n)
#define S390X_OFF_Y(n) (4 * n)

#define S390X_PAD(n) (n == 80 ? 14 : 0)

/*
 * Serialise an OSSL_FN scalar big-endian into a len-byte buffer, straight from
 * its little-endian limbs (never a BIGNUM).  A value wider than len is rejected.
 */
static int s390x_fn_scalar_be(unsigned char *out, int len, const OSSL_FN *scalar)
{
    const OSSL_FN_ULONG *w = ossl_fn_get_words(scalar);
    size_t dsize = ossl_fn_get_dsize(scalar), i, j;

    memset(out, 0, len);
    for (i = 0; i < dsize; i++) {
        OSSL_FN_ULONG d = w[i];

        for (j = 0; j < sizeof(d); j++) {
            size_t off = i * sizeof(d) + j;
            unsigned char b = (unsigned char)(d >> (8 * j));

            if (off < (size_t)len)
                out[len - 1 - off] = b;
            else if (b != 0)
                return 0;
        }
    }
    return 1;
}

/*
 * Shared PCC scalar multiplication core: r = scalar * point, where the scalar
 * is already serialised big-endian into a len-byte buffer.  point must be a
 * finite point.  Both the BIGNUM (ec_GFp_s390x_nistp_mul) and OSSL_FN
 * (ec_GFp_s390x_nistp_mul_fn) entry points wrap this; only the scalar
 * serialisation differs between them.
 */
static int ec_GFp_s390x_nistp_pcc(const EC_GROUP *group, EC_POINT *r,
    const unsigned char *scalar_be, const EC_POINT *point,
    unsigned int fc, int len, BN_CTX *ctx)
{
    unsigned char param[S390X_SIZE_PARAM];
    BIGNUM *x, *y;
    int rc = 0;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (x == NULL || y == NULL)
        goto ret;

    memset(param, 0, sizeof(param));
    memcpy(param + S390X_OFF_SCALAR(len), scalar_be, len);

    if (EC_POINT_get_affine_coordinates(group, point, x, y, ctx) != 1
        || BN_bn2binpad(x, param + S390X_OFF_SRC_X(len), len) == -1
        || BN_bn2binpad(y, param + S390X_OFF_SRC_Y(len), len) == -1
        || s390x_pcc(fc, param) != 0
        || BN_bin2bn(param + S390X_OFF_RES_X(len), len, x) == NULL
        || BN_bin2bn(param + S390X_OFF_RES_Y(len), len, y) == NULL
        || EC_POINT_set_affine_coordinates(group, r, x, y, ctx) != 1)
        goto ret;

    rc = 1;
ret:
    OPENSSL_cleanse(param, sizeof(param));
    BN_CTX_end(ctx);
    return rc;
}

static int ec_GFp_s390x_nistp_mul(const EC_GROUP *group, EC_POINT *r,
    const BIGNUM *scalar,
    size_t num, const EC_POINT *points[],
    const BIGNUM *scalars[],
    BN_CTX *ctx, unsigned int fc, int len)
{
    unsigned char scalar_be[S390X_SIZE_P521];
    const EC_POINT *point_ptr = NULL;
    const BIGNUM *scalar_ptr = NULL;
    BN_CTX *new_ctx = NULL;
    int rc = -1;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new_ex(group->libctx);
        if (ctx == NULL)
            return 0;
    }

    /*
     * Use PCC for EC keygen and ECDH key derivation:
     * scalar * generator and scalar * peer public key, scalar in [0,order).
     */
    if ((scalar != NULL && num == 0 && BN_is_negative(scalar) == 0)
        || (scalar == NULL && num == 1 && BN_is_negative(scalars[0]) == 0)) {

        if (num == 0) {
            point_ptr = EC_GROUP_get0_generator(group);
            scalar_ptr = scalar;
        } else {
            point_ptr = points[0];
            scalar_ptr = scalars[0];
        }

        if (EC_POINT_is_at_infinity(group, point_ptr)
            || BN_is_zero(scalar_ptr)) {
            rc = EC_POINT_set_to_infinity(group, r);
        } else if (BN_bn2binpad(scalar_ptr, scalar_be, len) != -1
            && ec_GFp_s390x_nistp_pcc(group, r, scalar_be, point_ptr, fc, len,
                ctx)) {
            rc = 1;
        }
    }

    /* Otherwise use default. */
    if (rc == -1)
        rc = ossl_ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);
    OPENSSL_cleanse(scalar_be, sizeof(scalar_be));
    BN_CTX_free(new_ctx);
    return rc;
}

/*-
 * OSSL_FN counterpart of ec_GFp_s390x_nistp_mul() and this method's 'mul_fn'
 * slot, reached from EC_POINT_mul_fn() when the scalar is secret.  It covers the
 * single-scalar cases the PCC path serves (scalar*G for key generation,
 * scalar*point for ECDH), which is all a secret scalar needs.
 *
 * Only the scalar changes representation: it is serialised big-endian straight
 * from the OSSL_FN limbs, so it never takes BIGNUM form, and then fed to the
 * shared ec_GFp_s390x_nistp_pcc() core.
 */
static int ec_GFp_s390x_nistp_mul_fn(const EC_GROUP *group, EC_POINT *r,
    const OSSL_FN *scalar, const EC_POINT *point,
    OSSL_FN_CTX *fnctx, unsigned int fc, int len)
{
    unsigned char scalar_be[S390X_SIZE_P521];
    BN_CTX *ctx = NULL;
    int ret = 0;

    (void)fnctx; /* fixed-width vectors; no OSSL_FN scratch context needed */

    if (scalar == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (point == NULL) {
        point = EC_GROUP_get0_generator(group);
        if (point == NULL) {
            ERR_raise(ERR_LIB_EC, EC_R_UNDEFINED_GENERATOR);
            return 0;
        }
    }
    if (EC_POINT_is_at_infinity(group, point) || OSSL_FN_is_zero(scalar))
        return EC_POINT_set_to_infinity(group, r);

    if (!s390x_fn_scalar_be(scalar_be, len, scalar)) {
        ERR_raise(ERR_LIB_EC, EC_R_COORDINATES_OUT_OF_RANGE);
        goto err;
    }
    if ((ctx = BN_CTX_new_ex(group->libctx)) == NULL)
        goto err;
    ret = ec_GFp_s390x_nistp_pcc(group, r, scalar_be, point, fc, len, ctx);

err:
    BN_CTX_free(ctx);
    OPENSSL_cleanse(scalar_be, sizeof(scalar_be));
    return ret;
}

#define MIN_ECDSA_SIGN_ORDERBITS 64

static ECDSA_SIG *ecdsa_s390x_nistp_sign_sig(const unsigned char *dgst,
    int dgstlen,
    const BIGNUM *kinv,
    const BIGNUM *r,
    EC_KEY *eckey,
    unsigned int fc, int len)
{
    unsigned char param[S390X_SIZE_PARAM];
    int ok = 0;
    BIGNUM *k;
    ECDSA_SIG *sig;
    const EC_GROUP *group;
    const BIGNUM *privkey;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
#ifdef FIPS_MODULE
    int order_bits;
#endif
    int off;

    if (dgstlen < 0) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_LENGTH);
        return NULL;
    }

    if (eckey == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return NULL;
    }

    group = EC_KEY_get0_group(eckey);
    if (group == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return NULL;
    }

    order = EC_GROUP_get0_order(group);
    if (order == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return NULL;
    }

    privkey = EC_KEY_get0_private_key(eckey);
    if (privkey == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return NULL;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return NULL;
    }

    k = BN_secure_new();
    sig = ECDSA_SIG_new();
    if (k == NULL || sig == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_ECDSA_LIB);
        goto ret;
    }

    sig->r = BN_new();
    sig->s = BN_new();
    if (sig->r == NULL || sig->s == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto ret;
    }

    memset(param, 0, sizeof(param));
    off = len - (dgstlen > len ? len : dgstlen);
    memcpy(param + S390X_OFF_H(len) + off, dgst, len - off);

    if (BN_bn2binpad(privkey, param + S390X_OFF_K(len), len) == -1) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto ret;
    }

    if (r == NULL || kinv == NULL) {
        if (len < 0) {
            ERR_raise(ERR_LIB_EC, EC_R_INVALID_LENGTH);
            goto ret;
        }
#ifdef FIPS_MODULE
        /* get random value of k using OpenSSL's RNG */
        bn_ctx = BN_CTX_secure_new_ex(ossl_ec_key_get_libctx(eckey));
        if (bn_ctx == NULL)
            goto ret;

        /* Preallocate space */
        order_bits = BN_num_bits(order);
        /* Check the number of bits here so that an infinite loop is not possible */
        if (order_bits < MIN_ECDSA_SIGN_ORDERBITS
            || !BN_set_bit(k, order_bits))
            goto ret;

        do {
            int res = 0;

            if (dgst != NULL)
                res = ossl_bn_gen_dsa_nonce_fixed_top(k, order, privkey,
                    dgst, dgstlen, bn_ctx);
            else
                res = ossl_bn_priv_rand_range_fixed_top(k, order, 0, bn_ctx);

            if (!res) {
                ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
                goto ret;
            }
        } while (ossl_bn_is_word_fixed_top(k, 0));

        if (BN_bn2binpad(k, param + S390X_OFF_RN(len), len) == -1) {
            ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
            goto ret;
        }

        /* Turns KDSA internal nonce-generation off. */
        fc |= S390X_KDSA_D;
#else
        /*
         * Generate random k and copy to param block. RAND_priv_bytes_ex
         * is used instead of BN_priv_rand_range or BN_generate_dsa_nonce
         * because kdsa instruction constructs an in-range, invertible nonce
         * internally implementing counter-measures for RNG weakness.
         */
        if (RAND_priv_bytes_ex(eckey->libctx, param + S390X_OFF_RN(len),
                (size_t)len, 0)
            != 1) {
            ERR_raise(ERR_LIB_EC, EC_R_RANDOM_NUMBER_GENERATION_FAILED);
            goto ret;
        }
#endif
    } else {
        bn_ctx = BN_CTX_secure_new_ex(ossl_ec_key_get_libctx(eckey));
        if (bn_ctx == NULL)
            goto ret;

        /* Reconstruct k = (k^-1)^-1. */
        if (ossl_ec_group_do_inverse_ord(group, k, kinv, bn_ctx) == 0
            || BN_bn2binpad(k, param + S390X_OFF_RN(len), len) == -1) {
            ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
            goto ret;
        }
        /* Turns KDSA internal nonce-generation off. */
        fc |= S390X_KDSA_D;
    }

    if (s390x_kdsa(fc, param, NULL, 0) != 0) {
        ERR_raise(ERR_LIB_EC, ERR_R_ECDSA_LIB);
        goto ret;
    }

    if (BN_bin2bn(param + S390X_OFF_R(len), len, sig->r) == NULL
        || BN_bin2bn(param + S390X_OFF_S(len), len, sig->s) == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto ret;
    }

    ok = 1;
ret:
    BN_CTX_free(bn_ctx);
    OPENSSL_cleanse(param, sizeof(param));
    if (ok != 1) {
        ECDSA_SIG_free(sig);
        sig = NULL;
    }
    BN_clear_free(k);
    return sig;
}

static int ecdsa_s390x_nistp_verify_sig(const unsigned char *dgst, int dgstlen,
    const ECDSA_SIG *sig, EC_KEY *eckey,
    unsigned int fc, int len)
{
    unsigned char param[S390X_SIZE_PARAM];
    int rc = -1;
    BN_CTX *ctx;
    BIGNUM *x, *y;
    const EC_GROUP *group;
    const EC_POINT *pubkey;
    int off;

    if (dgstlen < 0) {
        ERR_raise(ERR_LIB_EC, EC_R_INVALID_LENGTH);
        return -1;
    }

    if (sig == NULL || eckey == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return -1;
    }

    group = EC_KEY_get0_group(eckey);
    if (group == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return -1;
    }

    pubkey = EC_KEY_get0_public_key(eckey);
    if (pubkey == NULL) {
        ERR_raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS);
        return -1;
    }

    if (!EC_KEY_can_sign(eckey)) {
        ERR_raise(ERR_LIB_EC, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        return -1;
    }

    ctx = BN_CTX_new_ex(group->libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        return -1;
    }

    BN_CTX_start(ctx);

    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (x == NULL || y == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto ret;
    }

    memset(param, 0, sizeof(param));
    off = len - (dgstlen > len ? len : dgstlen);
    memcpy(param + S390X_OFF_H(len) + off, dgst, len - off);

    /* Check for invalid malformed signatures (r/s negative or too large) */
    if (BN_is_negative(sig->r) || BN_is_negative(sig->s)
        || BN_bn2binpad(sig->r, param + S390X_OFF_R(len) + S390X_PAD(len),
               len - S390X_PAD(len))
            == -1
        || BN_bn2binpad(sig->s, param + S390X_OFF_S(len) + S390X_PAD(len),
               len - S390X_PAD(len))
            == -1) {
        ERR_raise(ERR_LIB_EC, EC_R_BAD_SIGNATURE);
        rc = 0;
        goto ret;
    }

    if (EC_POINT_get_affine_coordinates(group, pubkey, x, y, ctx) != 1
        || BN_bn2binpad(x, param + S390X_OFF_X(len), len) == -1
        || BN_bn2binpad(y, param + S390X_OFF_Y(len), len) == -1) {
        ERR_raise(ERR_LIB_EC, ERR_R_BN_LIB);
        goto ret;
    }

    rc = s390x_kdsa(fc, param, NULL, 0);
    if (rc == 2)
        ERR_raise(ERR_LIB_EC, EC_R_BAD_SIGNATURE);
    rc = rc == 0 ? 1 : 0;
ret:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return rc;
}

#define EC_GFP_S390X_NISTP_METHOD(bits)                                             \
                                                                                    \
    static int ec_GFp_s390x_nistp##bits##_mul(const EC_GROUP *group,                \
        EC_POINT *r,                                                                \
        const BIGNUM *scalar,                                                       \
        size_t num,                                                                 \
        const EC_POINT *points[],                                                   \
        const BIGNUM *scalars[],                                                    \
        BN_CTX *ctx)                                                                \
    {                                                                               \
        return ec_GFp_s390x_nistp_mul(group, r, scalar, num, points,                \
            scalars, ctx,                                                           \
            S390X_SCALAR_MULTIPLY_P##bits,                                          \
            S390X_SIZE_P##bits);                                                    \
    }                                                                               \
                                                                                    \
    static int ec_GFp_s390x_nistp##bits##_mul_fn(const EC_GROUP *group,             \
        EC_POINT *r,                                                                \
        const OSSL_FN *scalar,                                                      \
        const EC_POINT *point,                                                      \
        OSSL_FN_CTX *fnctx)                                                         \
    {                                                                               \
        return ec_GFp_s390x_nistp_mul_fn(group, r, scalar, point, fnctx,            \
            S390X_SCALAR_MULTIPLY_P##bits,                                          \
            S390X_SIZE_P##bits);                                                    \
    }                                                                               \
                                                                                    \
    static size_t ec_GFp_s390x_nistp##bits##_mul_fn_ctx_size(                       \
        const EC_GROUP *group, EC_POINT *r, const OSSL_FN *scalar,                  \
        const EC_POINT *point)                                                      \
    {                                                                               \
        return OSSL_FN_CTX_SIZE_NONE;                                               \
    }                                                                               \
                                                                                    \
    static ECDSA_SIG *ecdsa_s390x_nistp##bits##_sign_sig(const unsigned char *dgst, \
        int dgstlen,                                                                \
        const BIGNUM *kinv,                                                         \
        const BIGNUM *r,                                                            \
        EC_KEY *eckey)                                                              \
    {                                                                               \
        return ecdsa_s390x_nistp_sign_sig(dgst, dgstlen, kinv, r, eckey,            \
            S390X_ECDSA_SIGN_P##bits,                                               \
            S390X_SIZE_P##bits);                                                    \
    }                                                                               \
                                                                                    \
    static int ecdsa_s390x_nistp##bits##_verify_sig(const unsigned char *dgst,      \
        int dgstlen,                                                                \
        const ECDSA_SIG *sig,                                                       \
        EC_KEY *eckey)                                                              \
    {                                                                               \
        return ecdsa_s390x_nistp_verify_sig(dgst, dgstlen, sig, eckey,              \
            S390X_ECDSA_VERIFY_P##bits,                                             \
            S390X_SIZE_P##bits);                                                    \
    }                                                                               \
                                                                                    \
    const EC_METHOD *EC_GFp_s390x_nistp##bits##_method(void)                        \
    {                                                                               \
        static const EC_METHOD EC_GFp_s390x_nistp##bits##_meth = {                  \
            EC_FLAGS_DEFAULT_OCT,                                                   \
            NID_X9_62_prime_field,                                                  \
            ossl_ec_GFp_simple_group_init,                                          \
            ossl_ec_GFp_simple_group_finish,                                        \
            ossl_ec_GFp_simple_group_clear_finish,                                  \
            ossl_ec_GFp_simple_group_copy,                                          \
            ossl_ec_GFp_simple_group_set_curve,                                     \
            ossl_ec_GFp_simple_group_get_curve,                                     \
            ossl_ec_GFp_simple_group_get_degree,                                    \
            ossl_ec_group_simple_order_bits,                                        \
            ossl_ec_GFp_simple_group_check_discriminant,                            \
            ossl_ec_GFp_simple_point_init,                                          \
            ossl_ec_GFp_simple_point_finish,                                        \
            ossl_ec_GFp_simple_point_clear_finish,                                  \
            ossl_ec_GFp_simple_point_copy,                                          \
            ossl_ec_GFp_simple_point_set_to_infinity,                               \
            ossl_ec_GFp_simple_point_set_affine_coordinates,                        \
            ossl_ec_GFp_simple_point_get_affine_coordinates,                        \
            NULL, /* point_set_compressed_coordinates */                            \
            NULL, /* point2oct */                                                   \
            NULL, /* oct2point */                                                   \
            ossl_ec_GFp_simple_add,                                                 \
            ossl_ec_GFp_simple_dbl,                                                 \
            ossl_ec_GFp_simple_invert,                                              \
            ossl_ec_GFp_simple_is_at_infinity,                                      \
            ossl_ec_GFp_simple_is_on_curve,                                         \
            ossl_ec_GFp_simple_cmp,                                                 \
            ossl_ec_GFp_simple_make_affine,                                         \
            ossl_ec_GFp_simple_points_make_affine,                                  \
            ec_GFp_s390x_nistp##bits##_mul,                                         \
            NULL, /* precompute_mult */                                             \
            NULL, /* have_precompute_mult */                                        \
            ossl_ec_GFp_simple_field_mul,                                           \
            ossl_ec_GFp_simple_field_sqr,                                           \
            NULL, /* field_div */                                                   \
            ossl_ec_GFp_simple_field_inv,                                           \
            NULL, /* field_encode */                                                \
            NULL, /* field_decode */                                                \
            NULL, /* field_set_to_one */                                            \
            ossl_ec_key_simple_priv2oct,                                            \
            ossl_ec_key_simple_oct2priv,                                            \
            NULL, /* set_private */                                                 \
            ossl_ec_key_simple_generate_key,                                        \
            ossl_ec_key_simple_check_key,                                           \
            ossl_ec_key_simple_generate_public_key,                                 \
            NULL, /* keycopy */                                                     \
            NULL, /* keyfinish */                                                   \
            ossl_ecdh_simple_compute_key,                                           \
            ossl_ecdsa_simple_sign_setup,                                           \
            ecdsa_s390x_nistp##bits##_sign_sig,                                     \
            ecdsa_s390x_nistp##bits##_verify_sig,                                   \
            NULL, /* field_inverse_mod_ord */                                       \
            ossl_ec_GFp_simple_blind_coordinates,                                   \
            ossl_ec_GFp_simple_ladder_pre,                                          \
            ossl_ec_GFp_simple_ladder_step,                                         \
            ossl_ec_GFp_simple_ladder_post,                                         \
            0, /* group_full_init */                                                \
            ec_GFp_s390x_nistp##bits##_mul_fn,                                      \
            ec_GFp_s390x_nistp##bits##_mul_fn_ctx_size                              \
        };                                                                          \
        static const EC_METHOD *ret;                                                \
                                                                                    \
        if ((OPENSSL_s390xcap_P.pcc[1]                                              \
                & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_P##bits))                      \
            && (OPENSSL_s390xcap_P.kdsa[0]                                          \
                & S390X_CAPBIT(S390X_ECDSA_VERIFY_P##bits))                         \
            && (OPENSSL_s390xcap_P.kdsa[0]                                          \
                & S390X_CAPBIT(S390X_ECDSA_SIGN_P##bits)))                          \
            ret = &EC_GFp_s390x_nistp##bits##_meth;                                 \
        else                                                                        \
            ret = EC_GFp_mont_method();                                             \
                                                                                    \
        return ret;                                                                 \
    }

EC_GFP_S390X_NISTP_METHOD(256)
EC_GFP_S390X_NISTP_METHOD(384)
EC_GFP_S390X_NISTP_METHOD(521)
