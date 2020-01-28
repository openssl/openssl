/*
 * Copyright 2002-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include "ec_local.h"
#include <openssl/err.h>

int EC_GROUP_check_named_curve(const EC_GROUP *group, int nist_only,
                               BN_CTX *ctx)
{
    int nid = NID_undef;
#ifndef FIPS_MODE
    BN_CTX *new_ctx = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL) {
            ECerr(EC_F_EC_GROUP_CHECK_NAMED_CURVE, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
#endif

    nid = ec_curve_nid_from_params(group, ctx);
    if (nid > 0 && nist_only && EC_curve_nid2nist(nid) == NULL)
        nid = NID_undef;

#ifndef FIPS_MODE
 err:
    BN_CTX_free(ctx);
#endif
    return nid;
}

int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)
{
#ifdef FIPS_MODE
    /*
    * ECC domain parameter validation.
    * See SP800-56A R3 5.5.2 "Assurances of Domain-Parameter Validity" Part 1b.
    */
    return EC_GROUP_check_named_curve(group, 1, ctx) >= 0 ? 1 : 0;
#else
    int ret = 0;
    const BIGNUM *order;
    BN_CTX *new_ctx = NULL;
    EC_POINT *point = NULL;

    if (group == NULL || group->meth == NULL) {
        ECerr(EC_F_EC_GROUP_CHECK, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Custom curves assumed to be correct */
    if ((group->meth->flags & EC_FLAGS_CUSTOM_CURVE) != 0)
        return 1;

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL) {
            ECerr(EC_F_EC_GROUP_CHECK, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    /* check the discriminant */
    if (!EC_GROUP_check_discriminant(group, ctx)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_DISCRIMINANT_IS_ZERO);
        goto err;
    }

    /* check the generator */
    if (group->generator == NULL) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }
    if (EC_POINT_is_on_curve(group, group->generator, ctx) <= 0) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_POINT_IS_NOT_ON_CURVE);
        goto err;
    }

    /* check the order of the generator */
    if ((point = EC_POINT_new(group)) == NULL)
        goto err;
    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_UNDEFINED_ORDER);
        goto err;
    }

    if (!EC_POINT_mul(group, point, order, NULL, NULL, ctx))
        goto err;
    if (!EC_POINT_is_at_infinity(group, point)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_INVALID_GROUP_ORDER);
        goto err;
    }

    ret = 1;

 err:
    BN_CTX_free(new_ctx);
    EC_POINT_free(point);
    return ret;
#endif /* FIPS_MODE */
}
