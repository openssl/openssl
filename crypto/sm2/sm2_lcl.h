/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ec.h>

#ifdef OPENSSL_NO_EC2M
static ossl_inline int sm2_get_curve(const EC_GROUP *group, BIGNUM *p,
                                     BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    return EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
}

static ossl_inline int sm2_get_affine_coordinates(const EC_GROUP *group,
                                                  const EC_POINT *p,
                                                  BIGNUM *x,
                                                  BIGNUM *y,
                                                  BN_CTX *ctx)
{
    return EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx);
}

static ossl_inline int sm2_set_affine_coordinates(const EC_GROUP *group,
                                                  EC_POINT *p,
                                                  const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  BN_CTX *ctx)
{
    return EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}
#else
static ossl_inline int sm2_get_curve(const EC_GROUP *group, BIGNUM *p,
                                     BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    return EC_METHOD_get_field_type(EC_GROUP_method_of(group))
               == NID_X9_62_prime_field
           ? EC_GROUP_get_curve_GFp(group, p, a, b, ctx)
           : EC_GROUP_get_curve_GF2m(group, p, a, b, ctx);
}

static ossl_inline int sm2_get_affine_coordinates(const EC_GROUP *group,
                                                  const EC_POINT *p,
                                                  BIGNUM *x,
                                                  BIGNUM *y,
                                                  BN_CTX *ctx)
{
    return EC_METHOD_get_field_type(EC_GROUP_method_of(group))
               == NID_X9_62_prime_field
           ? EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx)
           : EC_POINT_get_affine_coordinates_GF2m(group, p, x, y, ctx);
}

static ossl_inline int sm2_set_affine_coordinates(const EC_GROUP *group,
                                                  EC_POINT *p,
                                                  const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  BN_CTX *ctx)
{
    return EC_METHOD_get_field_type(EC_GROUP_method_of(group))
               == NID_X9_62_prime_field
           ? EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx)
           : EC_POINT_set_affine_coordinates_GF2m(group, p, x, y, ctx);
}
#endif
