/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include "ec_local.h"
#include "s390x_arch.h"

/* Size of parameter blocks */
#define S390X_SIZE_PARAM                4096

/* Size of fields in parameter blocks */
#define S390X_SIZE_P256                 32
#define S390X_SIZE_P384                 48
#define S390X_SIZE_P521                 80

/* Offsets of fields in PCC parameter blocks */
#define S390X_OFF_RES_X(n)              (0 * n)
#define S390X_OFF_RES_Y(n)              (1 * n)
#define S390X_OFF_SRC_X(n)              (2 * n)
#define S390X_OFF_SRC_Y(n)              (3 * n)
#define S390X_OFF_SCALAR(n)             (4 * n)

static int ec_GFp_s390x_nistp_mul(const EC_GROUP *group, EC_POINT *r,
                                  const BIGNUM *scalar,
                                  size_t num, const EC_POINT *points[],
                                  const BIGNUM *scalars[],
                                  BN_CTX *ctx, unsigned int fc, int len)
{
    unsigned char param[S390X_SIZE_PARAM];
    BIGNUM *x, *y;
    const EC_POINT *point_ptr = NULL;
    const BIGNUM *scalar_ptr = NULL;
    BN_CTX *new_ctx = NULL;
    int rc = -1;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    BN_CTX_start(ctx);

    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (x == NULL || y == NULL) {
        rc = 0;
        goto ret;
    }

    /*
     * Use PCC for EC keygen and ECDH key derivation:
     * scalar * generator and scalar * peer public key,
     * scalar in [0,order).
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

        if (EC_POINT_is_at_infinity(group, point_ptr) == 1
            || BN_is_zero(scalar_ptr)) {
            rc = EC_POINT_set_to_infinity(group, r);
            goto ret;
        }

        memset(&param, 0, sizeof(param));

        if (group->meth->point_get_affine_coordinates(group, point_ptr,
                                                      x, y, ctx) != 1
            || BN_bn2binpad(x, param + S390X_OFF_SRC_X(len), len) == -1
            || BN_bn2binpad(y, param + S390X_OFF_SRC_Y(len), len) == -1
            || BN_bn2binpad(scalar_ptr,
                            param + S390X_OFF_SCALAR(len), len) == -1
            || s390x_pcc(fc, param) != 0
            || BN_bin2bn(param + S390X_OFF_RES_X(len), len, x) == NULL
            || BN_bin2bn(param + S390X_OFF_RES_Y(len), len, y) == NULL
            || group->meth->point_set_affine_coordinates(group, r,
                                                         x, y, ctx) != 1)
            goto ret;

        rc = 1;
    }

ret:
    /* Otherwise use default. */
    if (rc == -1)
        rc = ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);
    OPENSSL_cleanse(param, sizeof(param));
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return rc;
}

#define EC_GFP_S390X_NISTP_METHOD(bits)                                 \
                                                                        \
static int ec_GFp_s390x_nistp##bits##_mul(const EC_GROUP *group,        \
                                          EC_POINT *r,                  \
                                          const BIGNUM *scalar,         \
                                          size_t num,                   \
                                          const EC_POINT *points[],     \
                                          const BIGNUM *scalars[],      \
                                          BN_CTX *ctx)                  \
{                                                                       \
    return ec_GFp_s390x_nistp_mul(group, r, scalar, num, points,        \
                                  scalars, ctx,                         \
                                  S390X_SCALAR_MULTIPLY_P##bits,        \
                                  S390X_SIZE_P##bits);                  \
}                                                                       \
                                                                        \
const EC_METHOD *EC_GFp_s390x_nistp##bits##_method(void)                \
{                                                                       \
    static const EC_METHOD EC_GFp_s390x_nistp##bits##_meth = {          \
        EC_FLAGS_DEFAULT_OCT,                                           \
        NID_X9_62_prime_field,                                          \
        ec_GFp_simple_group_init,                                       \
        ec_GFp_simple_group_finish,                                     \
        ec_GFp_simple_group_clear_finish,                               \
        ec_GFp_simple_group_copy,                                       \
        ec_GFp_simple_group_set_curve,                                  \
        ec_GFp_simple_group_get_curve,                                  \
        ec_GFp_simple_group_get_degree,                                 \
        ec_group_simple_order_bits,                                     \
        ec_GFp_simple_group_check_discriminant,                         \
        ec_GFp_simple_point_init,                                       \
        ec_GFp_simple_point_finish,                                     \
        ec_GFp_simple_point_clear_finish,                               \
        ec_GFp_simple_point_copy,                                       \
        ec_GFp_simple_point_set_to_infinity,                            \
        ec_GFp_simple_set_Jprojective_coordinates_GFp,                  \
        ec_GFp_simple_get_Jprojective_coordinates_GFp,                  \
        ec_GFp_simple_point_set_affine_coordinates,                     \
        ec_GFp_simple_point_get_affine_coordinates,                     \
        NULL, /* point_set_compressed_coordinates */                    \
        NULL, /* point2oct */                                           \
        NULL, /* oct2point */                                           \
        ec_GFp_simple_add,                                              \
        ec_GFp_simple_dbl,                                              \
        ec_GFp_simple_invert,                                           \
        ec_GFp_simple_is_at_infinity,                                   \
        ec_GFp_simple_is_on_curve,                                      \
        ec_GFp_simple_cmp,                                              \
        ec_GFp_simple_make_affine,                                      \
        ec_GFp_simple_points_make_affine,                               \
        ec_GFp_s390x_nistp##bits##_mul,                                 \
        NULL, /* precompute_mult */                                     \
        NULL, /* have_precompute_mult */                                \
        ec_GFp_simple_field_mul,                                        \
        ec_GFp_simple_field_sqr,                                        \
        NULL, /* field_div */                                           \
        ec_GFp_simple_field_inv,                                        \
        NULL, /* field_encode */                                        \
        NULL, /* field_decode */                                        \
        NULL, /* field_set_to_one */                                    \
        ec_key_simple_priv2oct,                                         \
        ec_key_simple_oct2priv,                                         \
        NULL, /* set_private */                                         \
        ec_key_simple_generate_key,                                     \
        ec_key_simple_check_key,                                        \
        ec_key_simple_generate_public_key,                              \
        NULL, /* keycopy */                                             \
        NULL, /* keyfinish */                                           \
        ecdh_simple_compute_key,                                        \
        NULL, /* field_inverse_mod_ord */                               \
        ec_GFp_simple_blind_coordinates,                                \
        ec_GFp_simple_ladder_pre,                                       \
        ec_GFp_simple_ladder_step,                                      \
        ec_GFp_simple_ladder_post                                       \
    };                                                                  \
    static const EC_METHOD *ret;                                        \
                                                                        \
    if (OPENSSL_s390xcap_P.pcc[1]                                       \
        & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_P##bits))                  \
        ret = &EC_GFp_s390x_nistp##bits##_meth;                         \
    else                                                                \
        ret = EC_GFp_mont_method();                                     \
                                                                        \
    return ret;                                                         \
}

EC_GFP_S390X_NISTP_METHOD(256)
EC_GFP_S390X_NISTP_METHOD(384)
EC_GFP_S390X_NISTP_METHOD(521)
