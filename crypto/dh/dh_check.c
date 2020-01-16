/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "dh_local.h"

/*-
 * Check that p and g are suitable enough
 *
 * p is odd
 * 1 < g < p - 1
 */
int DH_check_params_ex(const DH *dh)
{
    int errflags = 0;

    if (!DH_check_params(dh, &errflags))
        return 0;

    if ((errflags & DH_CHECK_P_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_CHECK_P_NOT_PRIME);
    if ((errflags & DH_NOT_SUITABLE_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_NOT_SUITABLE_GENERATOR);
    if ((errflags & DH_MODULUS_TOO_SMALL) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_MODULUS_TOO_SMALL);
    if ((errflags & DH_MODULUS_TOO_LARGE) != 0)
        DHerr(DH_F_DH_CHECK_PARAMS_EX, DH_R_MODULUS_TOO_LARGE);

    return errflags == 0;
}

int DH_check_params(const DH *dh, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL)
        goto err;

    if (!BN_is_odd(dh->params.p))
        *ret |= DH_CHECK_P_NOT_PRIME;
    if (BN_is_negative(dh->params.g)
        || BN_is_zero(dh->params.g)
        || BN_is_one(dh->params.g))
        *ret |= DH_NOT_SUITABLE_GENERATOR;
    if (BN_copy(tmp, dh->params.p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(dh->params.g, tmp) >= 0)
        *ret |= DH_NOT_SUITABLE_GENERATOR;
    if (BN_num_bits(dh->params.p) < DH_MIN_MODULUS_BITS)
        *ret |= DH_MODULUS_TOO_SMALL;
    if (BN_num_bits(dh->params.p) > OPENSSL_DH_MAX_MODULUS_BITS)
        *ret |= DH_MODULUS_TOO_LARGE;

    ok = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

/*-
 * Check that p is a safe prime and
 * g is a suitable generator.
 */
int DH_check_ex(const DH *dh)
{
    int errflags = 0;

    if (!DH_check(dh, &errflags))
        return 0;

    if ((errflags & DH_NOT_SUITABLE_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_NOT_SUITABLE_GENERATOR);
    if ((errflags & DH_CHECK_Q_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_Q_NOT_PRIME);
    if ((errflags & DH_CHECK_INVALID_Q_VALUE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_INVALID_Q_VALUE);
    if ((errflags & DH_CHECK_INVALID_J_VALUE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_INVALID_J_VALUE);
    if ((errflags & DH_UNABLE_TO_CHECK_GENERATOR) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_UNABLE_TO_CHECK_GENERATOR);
    if ((errflags & DH_CHECK_P_NOT_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_PRIME);
    if ((errflags & DH_CHECK_P_NOT_SAFE_PRIME) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_CHECK_P_NOT_SAFE_PRIME);
    if ((errflags & DH_MODULUS_TOO_SMALL) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_MODULUS_TOO_SMALL);
    if ((errflags & DH_MODULUS_TOO_LARGE) != 0)
        DHerr(DH_F_DH_CHECK_EX, DH_R_MODULUS_TOO_LARGE);

    return errflags == 0;
}

int DH_check(const DH *dh, int *ret)
{
    int ok = 0, r;
    BN_CTX *ctx = NULL;
    BIGNUM *t1 = NULL, *t2 = NULL;

    if (!DH_check_params(dh, ret))
        return 0;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL)
        goto err;

    if (dh->params.q != NULL) {
        if (BN_cmp(dh->params.g, BN_value_one()) <= 0)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        else if (BN_cmp(dh->params.g, dh->params.p) >= 0)
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        else {
            /* Check g^q == 1 mod p */
            if (!BN_mod_exp(t1, dh->params.g, dh->params.q, dh->params.p, ctx))
                goto err;
            if (!BN_is_one(t1))
                *ret |= DH_NOT_SUITABLE_GENERATOR;
        }
        r = BN_check_prime(dh->params.q, ctx, NULL);
        if (r < 0)
            goto err;
        if (!r)
            *ret |= DH_CHECK_Q_NOT_PRIME;
        /* Check p == 1 mod q  i.e. q divides p - 1 */
        if (!BN_div(t1, t2, dh->params.p, dh->params.q, ctx))
            goto err;
        if (!BN_is_one(t2))
            *ret |= DH_CHECK_INVALID_Q_VALUE;
        if (dh->params.j != NULL
            && BN_cmp(dh->params.j, t1))
            *ret |= DH_CHECK_INVALID_J_VALUE;
    }

    r = BN_check_prime(dh->params.p, ctx, NULL);
    if (r < 0)
        goto err;
    if (!r)
        *ret |= DH_CHECK_P_NOT_PRIME;
    else if (dh->params.q == NULL) {
        if (!BN_rshift1(t1, dh->params.p))
            goto err;
        r = BN_check_prime(t1, ctx, NULL);
        if (r < 0)
            goto err;
        if (!r)
            *ret |= DH_CHECK_P_NOT_SAFE_PRIME;
    }
    ok = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key)
{
    int errflags = 0;

    if (!DH_check_pub_key(dh, pub_key, &errflags))
        return 0;

    if ((errflags & DH_CHECK_PUBKEY_TOO_SMALL) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_TOO_SMALL);
    if ((errflags & DH_CHECK_PUBKEY_TOO_LARGE) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_TOO_LARGE);
    if ((errflags & DH_CHECK_PUBKEY_INVALID) != 0)
        DHerr(DH_F_DH_CHECK_PUB_KEY_EX, DH_R_CHECK_PUBKEY_INVALID);

    return errflags == 0;
}

int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *ret)
{
    int ok = 0;
    BIGNUM *tmp = NULL;
    BN_CTX *ctx = NULL;

    *ret = 0;
    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL || !BN_set_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) <= 0)
        *ret |= DH_CHECK_PUBKEY_TOO_SMALL;
    if (BN_copy(tmp, dh->params.p) == NULL || !BN_sub_word(tmp, 1))
        goto err;
    if (BN_cmp(pub_key, tmp) >= 0)
        *ret |= DH_CHECK_PUBKEY_TOO_LARGE;

    if (dh->params.q != NULL) {
        /* Check pub_key^q == 1 mod p */
        if (!BN_mod_exp(tmp, pub_key, dh->params.q, dh->params.p, ctx))
            goto err;
        if (!BN_is_one(tmp))
            *ret |= DH_CHECK_PUBKEY_INVALID;
    }

    ok = 1;
 err:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}
