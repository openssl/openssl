/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ec_lcl.h"
#include <openssl/err.h>
#include <openssl/rand_drbg.h>
#include <openssl/evp.h>

/*
 * Security strength is a number associated with the amount of work required to
 * break a cryptographic algorithm or system. For most operations such as key
 * generation/key agreement the acceptable range is [112, 256]. For legacy
 * reasons >= 80 is also allowed for decryption and signature verification
 * operations.
 */
#ifdef FIPS_MODE
# define OSSL_MIN_SECURITY_STRENGTH 112
# define OSSL_MIN_SECURITY_STRENGTH_LEGACY_USE 80
#else
# define OSSL_MIN_SECURITY_STRENGTH 80
#endif /* FIPS _MODE */
#define OSSL_MAX_SECURITY_STRENGTH RAND_DRBG_STRENGTH

static int ossl_check_security_strength(int security_bits, int operation)
{
#ifdef FIPS_MODE
    int min_strength = OSSL_MIN_SECURITY_STRENGTH;

    if (operation == EVP_PKEY_OP_UNDEFINED
            || (operation & (EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_DECRYPT)) != 0)
        min_strength = OSSL_MIN_SECURITY_STRENGTH_LEGACY_USE;
    return security_bits >= min_strength && security_bits <= RAND_DRBG_STRENGTH;
#endif
    return security_bits <= RAND_DRBG_STRENGTH;
}

/*
 * Check the strength that is supported by the EC domain parameters.
 * See SP800-131A R2 (Table 2 & 4).
 *
 * Params:
 *     group The EC group to check.
 *     max_strength If this is non zero, it checks that this value matches the
 *                  EC max strength. See SP800-56AR3 5.6.1.2.2 "Key Pair
 *                  Generation by Testing Candidates" Step (2).
 *     operation EVP_PKEY_OP flags. The operation type determines the minimum
 *               strength.
 * Returns: 1 if the group has a valid strength otherwise it returns 0.
 */
int ec_check_security_strength(const EC_GROUP *group, size_t max_strength,
                               int key_operation)
{
    int ecbits = ec_security_bits(group);

    return ossl_check_security_strength(ecbits, key_operation)
           && (key_operation != EVP_PKEY_OP_KEYGEN
               || max_strength == 0
               || max_strength == (size_t)ecbits);
}

/*
* ECC domain parameter validation.
* See SP800-56A R3 5.5.2 "Assurances of Domain-Parameter Validity" Part 1b.
*/
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)
{
#ifndef FIPS_MODE
    int ret = 0;
    const BIGNUM *order;
    BN_CTX *new_ctx = NULL;
    EC_POINT *point = NULL;

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
#else
    /* In fips mode just check that an approved elliptic curve group is used */
    if (!ec_check_security_strength(group, 0, EVP_PKEY_OP_UNDEFINED)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_INVALID_STRENGTH);
        return 0;
    }
    if (!ec_curve_check_approved(group)) {
        ECerr(EC_F_EC_GROUP_CHECK, EC_R_NOT_APPROVED);
        return 0;
    }
    return 1;
#endif /* FIPS_MODE */
}
