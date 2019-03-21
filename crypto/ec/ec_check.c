/*
 * Copyright 2002-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ec_lcl.h"
#include <openssl/err.h>

int EC_GROUP_check_named_curve(const EC_GROUP *group, int nist_only)
{
    int nid;

    nid = ec_curve_nid_from_params(group);
    if (nid > 0 && nist_only && EC_curve_nid2nist(nid) == NULL)
        nid = 0;
    return nid;
}

int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)
{
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
}
